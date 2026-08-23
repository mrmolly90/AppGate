package audit

import (
    "database/sql"
    "net/http"
    "go.uber.org/zap"
)

type Logger struct {
    db     *sql.DB
    logger *zap.SugaredLogger
}

func NewLogger(db *sql.DB, logger *zap.SugaredLogger) *Logger {
    return &Logger{db: db, logger: logger}
}

func (l *Logger) Middleware() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            next.ServeHTTP(w, r)
        })
    }
}