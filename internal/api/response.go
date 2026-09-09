package api

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func respondJSON(c *gin.Context, status int, data interface{}) {
	// Centralize JSON response writing so handlers stay focused on business flow.
	// The body is streamed with encoding/json rather than gin's own JSON renderer
	// so the wire format is unchanged: bare "application/json" without a charset
	// parameter, and the trailing newline Encode emits.
	c.Header("Content-Type", "application/json")
	c.Status(status)
	if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

func respondError(c *gin.Context, status int, msg string) {
	// Keep API error shape consistent across every endpoint.
	respondJSON(c, status, ErrorResponse{Error: msg})
}
