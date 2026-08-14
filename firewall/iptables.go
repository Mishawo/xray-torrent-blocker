package firewall

import (
    "fmt"
    "log"
    "net"
    "strings"
    "sync"

    "github.com/coreos/go-iptables/iptables"
)

type IPTablesFirewall struct {
    mu          sync.Mutex
    ipt         *iptables.IPTables // IPv4
    ip6t        *iptables.IPTables // IPv6
    chainName   string
    initialized bool
}

func NewIPTablesFirewall() *IPTablesFirewall {
    ipt, err4 := iptables.New()
    if err4 != nil {
        log.Printf("Warning: could not create iptables instance: %v", err4)
        ipt = nil
    }

    ip6t, err6 := iptables.NewWithProtocol(iptables.ProtocolIPv6)
    if err6 != nil {
        log.Printf("Warning: could not create ip6tables instance: %v", err6)
        ip6t = nil
    }

    return &IPTablesFirewall{
        ipt:         ipt,
        ip6t:        ip6t,
        chainName:   "TBLOCKER_BLOCKED",
        initialized: false,
    }
}

func (f *IPTablesFirewall) Initialize() error {
    if f.initialized {
        return nil
    }

    if f.ipt == nil && f.ip6t == nil {
        return fmt.Errorf("no iptables/ip6tables available")
    }

    log.Printf("Initializing iptables firewall...")

    if f.ipt != nil {
        if err := f.initializeProtocol(f.ipt); err != nil {
            log.Printf("Error initializing iptables (IPv4): %v", err)
        }
    }

    if f.ip6t != nil {
        if err := f.initializeProtocol(f.ip6t); err != nil {
            log.Printf("Error initializing ip6tables (IPv6): %v", err)
        }
    }

    f.initialized = true
    log.Printf("IPTables firewall initialized successfully with custom chain %s", f.chainName)
    return nil
}

// initializeProtocol handles the chain creation and jump rule for a specific IP protocol
func (f *IPTablesFirewall) initializeProtocol(ipt *iptables.IPTables) error {
    _, err := ipt.List("raw", "PREROUTING")
    if err != nil {
        return fmt.Errorf("not available: %v", err)
    }

    exists, err := ipt.ChainExists("raw", f.chainName)
    if err != nil {
        return err
    }

    if !exists {
        err = ipt.NewChain("raw", f.chainName)
        if err != nil {
            return err
        }
        log.Printf("Created chain %s in raw table", f.chainName)
    }

    rules, err := ipt.List("raw", "PREROUTING")
    if err != nil {
        return err
    }

    jumpRuleExists := false
    for _, rule := range rules {
        if strings.Contains(rule, f.chainName) {
            jumpRuleExists = true
            break
        }
    }

    if !jumpRuleExists {
        err = ipt.Insert("raw", "PREROUTING", 1, "-j", f.chainName)
        if err != nil {
            return err
        }
        log.Printf("Added jump rule to %s in PREROUTING chain", f.chainName)
    }

    return nil
}

// ensureInitialized safely handles the mutex locking for initialization
func (f *IPTablesFirewall) ensureInitialized() error {
    f.mu.Lock()
    defer f.mu.Unlock()
    if !f.initialized {
        return f.Initialize()
    }
    return nil
}

// getIPTablesInstance returns the correct firewall instance based on IP type
func (f *IPTablesFirewall) getIPTablesInstance(ip string) (*iptables.IPTables, error) {
    if err := f.ensureInitialized(); err != nil {
        return nil, err
    }

    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return nil, fmt.Errorf("invalid IP address: %s", ip)
    }

    if parsedIP.To4() != nil {
        if f.ipt == nil {
            return nil, fmt.Errorf("iptables (IPv4) not available")
        }
        return f.ipt, nil
    }

    if f.ip6t == nil {
        return nil, fmt.Errorf("ip6tables (IPv6) not available")
    }
    return f.ip6t, nil
}

func (f *IPTablesFirewall) BlockIP(ip string) error {
    ipt, err := f.getIPTablesInstance(ip)
    if err != nil {
        return err
    }

    // LOCK: Prevent race conditions when reading/writing rules
    f.mu.Lock()
    defer f.mu.Unlock()

    rules, err := ipt.List("raw", f.chainName)
    if err != nil {
        return err
    }

    for _, rule := range rules {
        if strings.Contains(rule, ip) && strings.Contains(rule, "DROP") {
            log.Printf("IP %s is already blocked in chain %s", ip, f.chainName)
            return nil
        }
    }

    err = ipt.Append("raw", f.chainName, "-s", ip, "-j", "DROP")
    if err != nil {
        log.Printf("Error blocking IP %s in chain %s: %v", ip, f.chainName, err)
        return err
    }

    log.Printf("IP %s blocked in chain %s", ip, f.chainName)
    return nil
}

func (f *IPTablesFirewall) UnblockIP(ip string) error {
    ipt, err := f.getIPTablesInstance(ip)
    if err != nil {
        return err
    }

    // LOCK: Prevent race conditions when deleting rules
    f.mu.Lock()
    defer f.mu.Unlock()

    err = ipt.Delete("raw", f.chainName, "-s", ip, "-j", "DROP")
    if err != nil {
        log.Printf("Error unblocking IP %s from chain %s: %v", ip, f.chainName, err)
        return err
    }

    log.Printf("IP %s unblocked from chain %s", ip, f.chainName)
    return nil
}

func (f *IPTablesFirewall) GetBlockedIPs() (map[string]bool, error) {
    if err := f.ensureInitialized(); err != nil {
        return nil, err
    }

    // LOCK: Prevent race conditions while listing rules
    f.mu.Lock()
    defer f.mu.Unlock()

    blockedIPs := make(map[string]bool)

    // Parse IPv4 rules
    if f.ipt != nil {
        rules, err := f.ipt.List("raw", f.chainName)
        if err == nil {
            for _, rule := range rules {
                if strings.Contains(rule, "DROP") {
                    // Safely extract IP from the -s flag
                    parts := strings.Fields(rule)
                    for i, part := range parts {
                        if part == "-s" && i+1 < len(parts) {
                            blockedIPs[parts[i+1]] = true
                            break
                        }
                    }
                }
            }
        }
    }

    // Parse IPv6 rules
    if f.ip6t != nil {
        rules, err := f.ip6t.List("raw", f.chainName)
        if err == nil {
            for _, rule := range rules {
                if strings.Contains(rule, "DROP") {
                    parts := strings.Fields(rule)
                    for i, part := range parts {
                        if part == "-s" && i+1 < len(parts) {
                            blockedIPs[parts[i+1]] = true
                            break
                        }
                    }
                }
            }
        }
    }

    return blockedIPs, nil
}

func (f *IPTablesFirewall) IsAvailable() bool {
    if f.ipt == nil && f.ip6t == nil {
        return false
    }

    if f.ipt != nil {
        if _, err := f.ipt.List("raw", "PREROUTING"); err == nil {
            return true
        }
    }

    if f.ip6t != nil {
        if _, err := f.ip6t.List("raw", "PREROUTING"); err == nil {
            return true
        }
    }

    return false
}

func (f *IPTablesFirewall) GetName() string {
    return "iptables"
}

func (f *IPTablesFirewall) FlushChain() error {
    if f.ipt != nil {
        if err := f.ipt.ClearChain("raw", f.chainName); err != nil {
            log.Printf("Error flushing IPv4 chain %s: %v", f.chainName, err)
        }
    }
    if f.ip6t != nil {
        if err := f.ip6t.ClearChain("raw", f.chainName); err != nil {
            log.Printf("Error flushing IPv6 chain %s: %v", f.chainName, err)
        }
    }
    log.Printf("Chain %s flushed successfully", f.chainName)
    return nil
}

func (f *IPTablesFirewall) RemoveChain() error {
    if f.ipt != nil {
        f.ipt.Delete("raw", "PREROUTING", "-j", f.chainName)
        f.ipt.ClearChain("raw", f.chainName)
        f.ipt.DeleteChain("raw", f.chainName)
    }
    if f.ip6t != nil {
        f.ip6t.Delete("raw", "PREROUTING", "-j", f.chainName)
        f.ip6t.ClearChain("raw", f.chainName)
        f.ip6t.DeleteChain("raw", f.chainName)
    }

    f.initialized = false
    log.Printf("Chain %s removed successfully", f.chainName)
    return nil
}

func (f *IPTablesFirewall) GetChainName() string {
    return f.chainName
}
