package storage

import (
    "encoding/json"
    "os"
    "path/filepath"
    "sync"
    "time"
)

type BlockedIP struct {
    IP           string    `json:"ip"`
    Username     string    `json:"username"`
    BlockedUntil time.Time `json:"blocked_until"`
}

type IPStorage struct {
    filepath  string
    mu        sync.RWMutex
    ips       map[string]BlockedIP
    scheduled map[string]bool // Added to track scheduled unblocks and prevent duplicates
    onUnblock func(ip string, delay time.Duration, username string)
}

func NewIPStorage(storageDir string, unblockFunc func(ip string, delay time.Duration, username string)) (*IPStorage, error) {
    if err := os.MkdirAll(storageDir, 0755); err != nil {
        return nil, err
    }

    storage := &IPStorage{
        filepath:  filepath.Join(storageDir, "blocked_ips.json"),
        ips:       make(map[string]BlockedIP),
        scheduled: make(map[string]bool),
        onUnblock: unblockFunc,
    }

    if err := storage.load(); err != nil && !os.IsNotExist(err) {
        return nil, err
    }

    storage.initializeUnblocks()

    go storage.cleanupRoutine()

    return storage, nil
}

func (s *IPStorage) initializeUnblocks() {
    now := time.Now()
    s.mu.RLock()
    for ip, info := range s.ips {
        if now.Before(info.BlockedUntil) {
            delay := info.BlockedUntil.Sub(now)
            s.scheduleUnblock(ip, delay, info.Username)
        } else {
            // Already expired before we restarted
            s.scheduleUnblock(ip, 0, info.Username)
        }
    }
    s.mu.RUnlock()
}

// scheduleUnblock ensures we only ever schedule the unblock goroutine once per IP
func (s *IPStorage) scheduleUnblock(ip string, delay time.Duration, username string) {
    s.mu.Lock()
    if s.scheduled[ip] {
        s.mu.Unlock()
        return // Already scheduled, do nothing
    }
    s.scheduled[ip] = true
    s.mu.Unlock()

    go func() {
        s.onUnblock(ip, delay, username)
        
        // Once the unblock logic is finished, remove it from the scheduled map
        s.mu.Lock()
        delete(s.scheduled, ip)
        s.mu.Unlock()
    }()
}

func (s *IPStorage) load() error {
    data, err := os.ReadFile(s.filepath)
    if err != nil {
        return err
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    return json.Unmarshal(data, &s.ips)
}

func (s *IPStorage) save() error {
    s.mu.RLock()
    data, err := json.MarshalIndent(s.ips, "", "  ")
    s.mu.RUnlock()

    if err != nil {
        return err
    }

    // Changed permissions to 0600 for better security (contains usernames/IPs)
    return os.WriteFile(s.filepath, data, 0600)
}

func (s *IPStorage) AddBlockedIP(ip, username string, duration time.Duration) error {
    blockedUntil := time.Now().Add(duration)

    s.mu.Lock()
    s.ips[ip] = BlockedIP{
        IP:           ip,
        Username:     username,
        BlockedUntil: blockedUntil,
    }
    s.mu.Unlock()

    s.scheduleUnblock(ip, duration, username)

    return s.save()
}

func (s *IPStorage) RemoveBlockedIP(ip string) error {
    s.mu.Lock()
    delete(s.ips, ip)
    delete(s.scheduled, ip) // Clean up scheduled map just in case
    s.mu.Unlock()

    return s.save()
}

func (s *IPStorage) IsBlocked(ip string) bool {
    s.mu.RLock()
    blocked, exists := s.ips[ip]
    if !exists {
        s.mu.RUnlock()
        return false
    }

    // IMMEDIATE CLEANUP: If it's expired, remove it right now instead of returning false
    if time.Now().After(blocked.BlockedUntil) {
        s.mu.RUnlock()
        s.RemoveBlockedIP(ip) 
        return false
    }

    s.mu.RUnlock()
    return true
}

func (s *IPStorage) GetBlockedIPs() map[string]BlockedIP {
    s.mu.RLock()
    defer s.mu.RUnlock()

    result := make(map[string]BlockedIP, len(s.ips))
    for k, v := range s.ips {
        result[k] = v
    }

    return result
}

func (s *IPStorage) cleanupRoutine() {
    // Reduced from 5 minutes to 1 minute for better accuracy
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        now := time.Now()
        var ipsToCheck []struct {
            ip       string
            username string
        }

        s.mu.RLock()
        for ip, blocked := range s.ips {
            if now.After(blocked.BlockedUntil) {
                ipsToCheck = append(ipsToCheck, struct {
                    ip       string
                    username string
                }{ip: ip, username: blocked.Username})
            }
        }
        s.mu.RUnlock()

        // Use the safe scheduling method
        for _, item := range ipsToCheck {
            s.scheduleUnblock(item.ip, 0, item.username)
        }
    }
}