package utils

import (
    "bytes"
    "encoding/json"
    "fmt"
    "html"
    "log"
    "net/http"
    "sync"
    "tblocker/config"
    "time"
)

type StrikeInfo struct {
    Count    int
    LastPort string
    LastSeen time.Time
}

var (
    strikeMu      sync.Mutex
    strikeRecords = make(map[string]StrikeInfo)
)

func init() {
    // Start background routine to clean up old strikes
    go cleanupStrikes()
}

func cleanupStrikes() {
    ticker := time.NewTicker(10 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        strikeMu.Lock()
        now := time.Now()
        for user, info := range strikeRecords {
            // If the user hasn't triggered a strike in StrikeTimeout, reset them
            if now.Sub(info.LastSeen) > config.StrikeTimeout {
                delete(strikeRecords, user)
            }
        }
        strikeMu.Unlock()
    }
}

// RecordStrike tracks user attempts and sends a Telegram alert if they exceed MaxStrikes
func RecordStrike(username, port string) {
    // If MaxStrikes is 0, the strike system is disabled
    if config.MaxStrikes <= 0 {
        return
    }

    strikeMu.Lock()
    info := strikeRecords[username]
    info.Count++
    info.LastPort = port
    info.LastSeen = time.Now()
    strikeRecords[username] = info

    // Check if we just hit the exact strike limit
    shouldAlert := info.Count == config.MaxStrikes
    strikeMu.Unlock()

    if shouldAlert {
        go SendTelegramAlert(username, port, info.Count)
    }
}

func SendTelegramAlert(username, port string, attempts int) {
    if config.TelegramBotToken == "" || config.TelegramChatID == "" {
        log.Println("Strike limit reached, but Telegram Bot Token or Chat ID is not configured.")
        return
    }

    // Escape variables to prevent Telegram HTML parsing errors
    escapedUsername := html.EscapeString(username)
    escapedServer := html.EscapeString(config.Hostname)

    text := fmt.Sprintf(
        "🚨 <b>Repeat Torrent Offender Detected!</b>\n\n"+
            "👤 <b>User:</b> %s\n"+
            "🌐 <b>Server:</b> %s\n"+
            "🔁 <b>Attempts:</b> %d\n"+
            "🚪 <b>Last Torrent Port:</b> %s\n"+
            "🕒 <b>Time:</b> %s",
        escapedUsername,
        escapedServer,
        attempts,
        port,
        time.Now().Format(time.RFC3339),
    )

    payload := map[string]string{
        "chat_id":    config.TelegramChatID,
        "parse_mode": "HTML",
        "text":       text,
    }

    payloadBytes, err := json.Marshal(payload)
    if err != nil {
        log.Printf("Error marshaling Telegram payload: %v", err)
        return
    }

    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.TelegramBotToken)
    req, err := http.NewRequest("POST", url, bytes.NewReader(payloadBytes))
    if err != nil {
        log.Printf("Error creating Telegram request: %v", err)
        return
    }
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error sending Telegram alert: %v", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        log.Printf("Telegram returned unexpected status code: %d", resp.StatusCode)
    } else {
        log.Printf("Telegram alert sent for repeat offender: %s", username)
    }
}
