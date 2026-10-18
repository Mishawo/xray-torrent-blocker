package firewall

import (
    "fmt"
    "log"
    "strings"

    "github.com/coreos/go-iptables/iptables"
)

type IPTablesFirewall struct {
    ipt         *iptables.IPTables
    ip6t        *iptables.IPTables
    ipv6Enabled bool
    chainName   string
    initialized bool
}

func NewIPTablesFirewall() *IPTablesFirewall {
    ipt, err := iptables.New()
    if err != nil {
        log.Printf("Error creating iptables instance: %v", err)
        return &IPTablesFirewall{
            chainName:   "TBLOCKER_BLOCKED",
            initialized: false,
        }
    }

    // IPv6 instance is optional: when ip6tables is unavailable, blocking
    // continues to work in IPv4-only mode.
    ip6t, err6 := iptables.New(iptables.IPFamily(iptables.ProtocolIPv6))
    if err6 != nil {
        log.Printf("Warning: ip6tables is not available, IPv6 addresses will not be blocked: %v", err6)
    }

    return &IPTablesFirewall{
        ipt:         ipt,
        ip6t:        ip6t,
        ipv6Enabled: err6 == nil,
        chainName:   "TBLOCKER_BLOCKED",
        initialized: false,
    }
}

// instanceForIP returns the firewall instance responsible for the given IP
// (ip6tables for IPv6 addresses, iptables for everything else).
func (f *IPTablesFirewall) instanceForIP(ip string) (*iptables.IPTables, error) {
    if strings.Contains(ip, ":") {
        if !f.ipv6Enabled || f.ip6t == nil {
            return nil, fmt.Errorf("IPv6 blocking is not available (ip6tables)")
        }
        return f.ip6t, nil
    }

    if f.ipt == nil {
        return nil, fmt.Errorf("iptables not available")
    }
    return f.ipt, nil
}

// initializeIPv6 prepares the IPv6 chain and jump rule. Any failure only
// disables IPv6 blocking - IPv4 blocking must keep working.
func (f *IPTablesFirewall) initializeIPv6() {
    if f.ip6t == nil {
        f.ipv6Enabled = false
        return
    }

    exists, err := f.ip6t.ChainExists("raw", f.chainName)
    if err != nil {
        log.Printf("Warning: could not check IPv6 chain existence, IPv6 blocking disabled: %v", err)
        f.ipv6Enabled = false
        return
    }

    if !exists {
        if err := f.ip6t.NewChain("raw", f.chainName); err != nil {
            log.Printf("Warning: could not create IPv6 chain %s, IPv6 blocking disabled: %v", f.chainName, err)
            f.ipv6Enabled = false
            return
        }
        log.Printf("Created IPv6 chain %s in raw table", f.chainName)
    }

    rules, err := f.ip6t.List("raw", "PREROUTING")
    if err != nil {
        log.Printf("Warning: could not list IPv6 PREROUTING rules, IPv6 blocking disabled: %v", err)
        f.ipv6Enabled = false
        return
    }

    for _, rule := range rules {
        if strings.Contains(rule, f.chainName) {
            f.ipv6Enabled = true
            log.Printf("IPv6 firewall initialized with chain %s", f.chainName)
            return
        }
    }

    if err := f.ip6t.Insert("raw", "PREROUTING", 1, "-j", f.chainName); err != nil {
        log.Printf("Warning: could not add IPv6 jump rule, IPv6 blocking disabled: %v", err)
        f.ipv6Enabled = false
        return
    }

    log.Printf("Added IPv6 jump rule to %s in PREROUTING chain", f.chainName)
    f.ipv6Enabled = true
}

func (f *IPTablesFirewall) Initialize() error {
    if f.initialized {
        return nil
    }

    if f.ipt == nil {
        return fmt.Errorf("iptables not available")
    }

    _, err := f.ipt.List("raw", "PREROUTING")
    if err != nil {
        log.Printf("IPTables is not available on this system: %v", err)
        return fmt.Errorf("iptables not available: %v", err)
    }

    log.Printf("Initializing iptables firewall...")

    exists, err := f.ipt.ChainExists("raw", f.chainName)
    if err != nil {
        log.Printf("Error checking chain existence: %v", err)
        return err
    }

    if !exists {
        err = f.ipt.NewChain("raw", f.chainName)
        if err != nil {
            log.Printf("Error creating chain %s: %v", f.chainName, err)
            return err
        }
        log.Printf("Created chain %s in raw table", f.chainName)
    }

    rules, err := f.ipt.List("raw", "PREROUTING")
    if err != nil {
        log.Printf("Error listing PREROUTING rules: %v", err)
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
        err = f.ipt.Insert("raw", "PREROUTING", 1, "-j", f.chainName)
        if err != nil {
            log.Printf("Error adding jump rule to %s: %v", f.chainName, err)
            return err
        }
        log.Printf("Added jump rule to %s in PREROUTING chain", f.chainName)
    }

    // IPv6 setup is best-effort and never fails initialization
    f.initializeIPv6()

    f.initialized = true
    log.Printf("IPTables firewall initialized successfully with custom chain %s", f.chainName)
    return nil
}

func (f *IPTablesFirewall) BlockIP(ip string) error {
    if !f.initialized {
        if err := f.Initialize(); err != nil {
            return err
        }
    }

    target, err := f.instanceForIP(ip)
    if err != nil {
        return err
    }

    rules, err := target.List("raw", f.chainName)
    if err != nil {
        log.Printf("Error getting rules from chain %s: %v", f.chainName, err)
        return err
    }

    for _, rule := range rules {
        if strings.Contains(rule, ip) && strings.Contains(rule, "DROP") {
            log.Printf("IP %s is already blocked in chain %s", ip, f.chainName)
            return nil
        }
    }

    err = target.Append("raw", f.chainName, "-s", ip, "-j", "DROP")
    if err != nil {
        log.Printf("Error blocking IP %s in chain %s: %v", ip, f.chainName, err)
        return err
    }

    log.Printf("IP %s blocked in chain %s", ip, f.chainName)
    return nil
}

func (f *IPTablesFirewall) UnblockIP(ip string) error {
    if !f.initialized {
        if err := f.Initialize(); err != nil {
            return err
        }
    }

    target, err := f.instanceForIP(ip)
    if err != nil {
        return err
    }

    err = target.Delete("raw", f.chainName, "-s", ip, "-j", "DROP")
    if err != nil {
        log.Printf("Error unblocking IP %s from chain %s: %v", ip, f.chainName, err)
        return err
    }

    log.Printf("IP %s unblocked from chain %s", ip, f.chainName)
    return nil
}

// extractSourceIP returns the source address from an iptables rule line
// (e.g. "-A TBLOCKER_BLOCKED -s 1.2.3.4/32 -j DROP" -> "1.2.3.4").
func extractSourceIP(rule string) string {
    fields := strings.Fields(rule)
    for i, field := range fields {
        if field == "-s" && i+1 < len(fields) {
            src := fields[i+1]
            if idx := strings.Index(src, "/"); idx != -1 {
                src = src[:idx]
            }
            return src
        }
    }
    return ""
}

func collectBlockedRules(rules []string, into map[string]bool) {
    for _, rule := range rules {
        if !strings.Contains(rule, "DROP") {
            continue
        }

        src := extractSourceIP(rule)
        if src == "" || src == "0.0.0.0" || src == "::" {
            continue
        }

        into[src] = true
    }
}

func (f *IPTablesFirewall) GetBlockedIPs() (map[string]bool, error) {
    if f.ipt == nil {
        return nil, fmt.Errorf("iptables not available")
    }

    if !f.initialized {
        if err := f.Initialize(); err != nil {
            return nil, err
        }
    }

    blockedIPs := make(map[string]bool)

    rules, err := f.ipt.List("raw", f.chainName)
    if err != nil {
        log.Printf("Error getting rules from chain %s: %v", f.chainName, err)
        return nil, err
    }
    collectBlockedRules(rules, blockedIPs)

    if f.ipv6Enabled && f.ip6t != nil {
        v6rules, err := f.ip6t.List("raw", f.chainName)
        if err != nil {
            log.Printf("Warning: could not list IPv6 rules: %v", err)
        } else {
            collectBlockedRules(v6rules, blockedIPs)
        }
    }

    return blockedIPs, nil
}

func (f *IPTablesFirewall) IsAvailable() bool {
    if f.ipt == nil {
        return false
    }

    _, err := f.ipt.List("raw", "PREROUTING")
    return err == nil
}

func (f *IPTablesFirewall) GetName() string {
    return "iptables"
}

func (f *IPTablesFirewall) FlushChain() error {
    if f.ipt == nil {
        return fmt.Errorf("iptables not available")
    }

    if !f.initialized {
        return nil
    }

    err := f.ipt.ClearChain("raw", f.chainName)
    if err != nil {
        log.Printf("Error flushing chain %s: %v", f.chainName, err)
        return err
    }

    if f.ipv6Enabled && f.ip6t != nil {
        if err := f.ip6t.ClearChain("raw", f.chainName); err != nil {
            log.Printf("Warning: could not flush IPv6 chain %s: %v", f.chainName, err)
        }
    }

    log.Printf("Chain %s flushed successfully", f.chainName)
    return nil
}

func (f *IPTablesFirewall) RemoveChain() error {
    if f.ipt == nil {
        return fmt.Errorf("iptables not available")
    }

    if !f.initialized {
        return nil
    }

    err := f.ipt.Delete("raw", "PREROUTING", "-j", f.chainName)
    if err != nil {
        log.Printf("Warning: Could not remove jump rule to %s: %v", f.chainName, err)
    }

    err = f.ipt.ClearChain("raw", f.chainName)
    if err != nil {
        log.Printf("Error clearing chain %s: %v", f.chainName, err)
        return err
    }

    err = f.ipt.DeleteChain("raw", f.chainName)
    if err != nil {
        log.Printf("Error deleting chain %s: %v", f.chainName, err)
        return err
    }

    if f.ipv6Enabled && f.ip6t != nil {
        if err := f.ip6t.Delete("raw", "PREROUTING", "-j", f.chainName); err != nil {
            log.Printf("Warning: Could not remove IPv6 jump rule: %v", err)
        }
        if err := f.ip6t.ClearChain("raw", f.chainName); err != nil {
            log.Printf("Warning: could not clear IPv6 chain %s: %v", f.chainName, err)
        } else if err := f.ip6t.DeleteChain("raw", f.chainName); err != nil {
            log.Printf("Warning: could not delete IPv6 chain %s: %v", f.chainName, err)
        }
    }

    f.initialized = false
    log.Printf("Chain %s removed successfully", f.chainName)
    return nil
}

func (f *IPTablesFirewall) GetChainName() string {
    return f.chainName
}
