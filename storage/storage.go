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
    onUnblock func(ip string, delay time.Duration, username string)
}

func NewIPStorage(storageDir string, unblockFunc func(ip string, delay time.Duration, username string)) (*IPStorage, error) {
    if err := os.MkdirAll(storageDir, 0755); err != nil {
        return nil, err
    }

    storage := &IPStorage{
        filepath:  filepath.Join(storageDir, "blocked_ips.json"),
        ips:       make(map[string]BlockedIP),
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
            go s.onUnblock(ip, delay, info.Username)
        } else {
            go s.onUnblock(ip, 0, info.Username)
        }
    }
    s.mu.RUnlock()
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
    // Hold the write lock for the whole commit so saves can never land
    // out-of-order (an older snapshot overwriting a newer one).
    s.mu.Lock()
    defer s.mu.Unlock()

    data, err := json.MarshalIndent(s.ips, "", "  ")
    if err != nil {
        return err
    }

    // Write to a unique temporary file first, then atomically rename it over
    // the real file so a crash mid-write can never corrupt blocked_ips.json
    tmpFile, err := os.CreateTemp(filepath.Dir(s.filepath), filepath.Base(s.filepath)+".tmp-")
    if err != nil {
        return err
    }
    tmpPath := tmpFile.Name()

    if _, err := tmpFile.Write(data); err != nil {
        tmpFile.Close()
        os.Remove(tmpPath)
        return err
    }

    if err := tmpFile.Chmod(0644); err != nil {
        tmpFile.Close()
        os.Remove(tmpPath)
        return err
    }

    if err := tmpFile.Close(); err != nil {
        os.Remove(tmpPath)
        return err
    }

    if err := os.Rename(tmpPath, s.filepath); err != nil {
        os.Remove(tmpPath)
        return err
    }

    return nil
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

    go s.onUnblock(ip, duration, username)

    return s.save()
}

func (s *IPStorage) RemoveBlockedIP(ip string) error {
    s.mu.Lock()
    delete(s.ips, ip)
    s.mu.Unlock()

    return s.save()
}

func (s *IPStorage) IsBlocked(ip string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()

    blocked, exists := s.ips[ip]
    if !exists {
        return false
    }

    if time.Now().After(blocked.BlockedUntil) {
        return false
    }

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
    ticker := time.NewTicker(5 * time.Minute)
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

        for _, item := range ipsToCheck {
            go s.onUnblock(item.ip, 0, item.username)
        }
    }
}
