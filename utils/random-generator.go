package utils

import (
    "time"
    "math/rand"
)

func init() {
    rand.Seed(time.Now().UnixNano())
}

const letterRunes = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func RandString(n int) string {
    b := make([]byte, n)
    for i := range b {
        b[i] = letterRunes[rand.Int63() % int64(len(letterRunes))]
    }
    return string(b)
}