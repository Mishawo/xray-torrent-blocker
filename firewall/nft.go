package firewall

import (
    "fmt"
    "log"
    "net"
    "strings"
    "sync"

    "github.com/google/nftables"
    "github.com/google/nftables/expr"
)

const (
    setV4Name = "TBLOCKER_IPV4"
    setV6Name = "TBLOCKER_IPV6"
)

type NFTFirewall struct {
    mu          sync.Mutex
    conn        *nftables.Conn
    initialized bool
}

func NewNFTFirewall() *NFTFirewall {
    return &NFTFirewall{
        conn:        &nftables.Conn{},
        initialized: false,
    }
}

func (f *NFTFirewall) Initialize() error {
    if f.initialized {
        return nil
    }

    log.Printf("Initializing nftables firewall...")

    table := &nftables.Table{
        Family: nftables.TableFamilyINet,
        Name:   "tblocker",
    }
    f.conn.AddTable(table)

    policy := nftables.ChainPolicyAccept
    chain := &nftables.Chain{
        Name:     "TBLOCKER_BLOCKED",
        Table:    table,
        Type:     nftables.ChainTypeFilter,
        Hooknum:  nftables.ChainHookPrerouting,
        Priority: nftables.ChainPriorityFilter,
        Policy:   &policy,
    }
    f.conn.AddChain(chain)

    // Create IPv4 Set
    setV4 := &nftables.Set{
        Table:   table,
        Name:    setV4Name,
        KeyType: nftables.TypeIPAddr,
    }
    f.conn.AddSet(setV4, []nftables.SetElement{})

    // Create IPv6 Set
    setV6 := &nftables.Set{
        Table:   table,
        Name:    setV6Name,
        KeyType: nftables.TypeIP6Addr,
    }
    f.conn.AddSet(setV6, []nftables.SetElement{})

    // Add IPv4 Rule (Offset 12, Len 4)
    if !f.ruleExists(table, chain, setV4Name, 12, 4) {
        ruleV4 := &nftables.Rule{
            Table: table,
            Chain: chain,
            Exprs: []expr.Any{
                &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
                &expr.Lookup{SourceRegister: 1, SetName: setV4.Name, SetID: setV4.ID},
                &expr.Verdict{Kind: expr.VerdictDrop},
            },
        }
        f.conn.AddRule(ruleV4)
    }

    // Add IPv6 Rule (Offset 8, Len 16)
    if !f.ruleExists(table, chain, setV6Name, 8, 16) {
        ruleV6 := &nftables.Rule{
            Table: table,
            Chain: chain,
            Exprs: []expr.Any{
                &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
                &expr.Lookup{SourceRegister: 1, SetName: setV6.Name, SetID: setV6.ID},
                &expr.Verdict{Kind: expr.VerdictDrop},
            },
        }
        f.conn.AddRule(ruleV6)
    }

    err := f.conn.Flush()
    if err != nil {
        log.Printf("Error initializing nftables: %v", err)
        return fmt.Errorf("failed to initialize nftables: %v", err)
    }

    log.Printf("Nftables firewall initialized successfully")
    f.initialized = true
    return nil
}

// ruleExists checks if a rule for a specific set and IP protocol exists
func (f *NFTFirewall) ruleExists(table *nftables.Table, chain *nftables.Chain, setName string, offset, length uint32) bool {
    rules, err := f.conn.GetRules(table, chain)
    if err != nil {
        return false
    }

    for _, rule := range rules {
        if len(rule.Exprs) >= 3 {
            if payload, ok := rule.Exprs[0].(*expr.Payload); ok {
                if payload.DestRegister == 1 && payload.Base == expr.PayloadBaseNetworkHeader &&
                    payload.Offset == offset && payload.Len == length {
                    if lookup, ok := rule.Exprs[1].(*expr.Lookup); ok {
                        if lookup.SourceRegister == 1 && lookup.SetName == setName {
                            if verdict, ok := rule.Exprs[2].(*expr.Verdict); ok {
                                if verdict.Kind == expr.VerdictDrop {
                                    return true
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return false
}

// ensureInitialized safely handles the mutex locking for initialization
func (f *NFTFirewall) ensureInitialized() error {
    f.mu.Lock()
    defer f.mu.Unlock()
    if !f.initialized {
        return f.Initialize()
    }
    return nil
}

func (f *NFTFirewall) BlockIP(ip string) error {
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return fmt.Errorf("invalid IP address: %s", ip)
    }

    if err := f.ensureInitialized(); err != nil {
        return fmt.Errorf("failed to initialize firewall: %v", err)
    }

    table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "tblocker"}
    var set *nftables.Set
    var keyBytes []byte

    if v4 := parsedIP.To4(); v4 != nil {
        set = &nftables.Set{Table: table, Name: setV4Name, KeyType: nftables.TypeIPAddr}
        keyBytes = v4
    } else {
        set = &nftables.Set{Table: table, Name: setV6Name, KeyType: nftables.TypeIP6Addr}
        keyBytes = parsedIP.To16()
    }

    element := nftables.SetElement{Key: keyBytes}
    f.conn.SetAddElements(set, []nftables.SetElement{element})

    if err := f.conn.Flush(); err != nil {
        // If the IP is already in the set, nftables returns an "exists" error. We ignore it.
        if strings.Contains(err.Error(), "exists") {
            return nil
        }
        log.Printf("Error adding IP %s to nftables set: %v", ip, err)
        return fmt.Errorf("failed to add IP %s to nftables set: %v", ip, err)
    }

    log.Printf("IP %s blocked with nftables", ip)
    return nil
}

func (f *NFTFirewall) UnblockIP(ip string) error {
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return fmt.Errorf("invalid IP address: %s", ip)
    }

    if err := f.ensureInitialized(); err != nil {
        return fmt.Errorf("failed to initialize firewall: %v", err)
    }

    table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "tblocker"}
    var set *nftables.Set
    var keyBytes []byte

    if v4 := parsedIP.To4(); v4 != nil {
        set = &nftables.Set{Table: table, Name: setV4Name, KeyType: nftables.TypeIPAddr}
        keyBytes = v4
    } else {
        set = &nftables.Set{Table: table, Name: setV6Name, KeyType: nftables.TypeIP6Addr}
        keyBytes = parsedIP.To16()
    }

    element := nftables.SetElement{Key: keyBytes}
    f.conn.SetDeleteElements(set, []nftables.SetElement{element})

    if err := f.conn.Flush(); err != nil {
        log.Printf("Error unblocking IP %s with nftables: %v", ip, err)
        return fmt.Errorf("failed to unblock IP %s with nftables: %v", ip, err)
    }

    log.Printf("IP %s unblocked with nftables", ip)
    return nil
}

func (f *NFTFirewall) GetBlockedIPs() (map[string]bool, error) {
    if err := f.ensureInitialized(); err != nil {
        return nil, err
    }

    table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "tblocker"}

    sets, err := f.conn.GetSets(table)
    if err != nil {
        return nil, fmt.Errorf("failed to get sets via API: %v", err)
    }

    blockedIPs := make(map[string]bool)
    for _, s := range sets {
        // Read both IPv4 and IPv6 sets
        if s.Name == setV4Name || s.Name == setV6Name {
            elements, err := f.conn.GetSetElements(s)
            if err != nil {
                log.Printf("Error listing nftables set %s via API: %v", s.Name, err)
                continue
            }

            for _, element := range elements {
                if len(element.Key) > 0 {
                    ip := net.IP(element.Key).String()
                    blockedIPs[ip] = true
                }
            }
        }
    }

    return blockedIPs, nil
}

func (f *NFTFirewall) IsAvailable() bool {
    return isCommandAvailable("nft")
}

func (f *NFTFirewall) GetName() string {
    return "nftables"
}
