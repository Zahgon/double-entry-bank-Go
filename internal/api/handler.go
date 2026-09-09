// Package api exposes HTTP handlers, middleware, and response types for the ledger service.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/internal/db"
	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/internal/service"
	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/postgres/sqlc"
)

// Handler serves HTTP requests backed by the ledger and store layers.
type Handler struct {
	ledger *service.LedgerService
	store  *db.Store
}

// NewHandler constructs a Handler with the required service and persistence dependencies.
func NewHandler(ledger *service.LedgerService, store *db.Store) *Handler {
	return &Handler{ledger: ledger, store: store}
}

// Register godoc
// @Summary      Register a new user
// @Description  Creates a new user with email and hashed password, returns user details and JWT token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body    body      object{email=string,password=string}  true  "User registration details"
// @Success      201     {object}  RegisterResponse
// @Failure      400     {object}  ErrorResponse
// @Failure      409     {object}  ErrorResponse
// @Failure      500     {object}  ErrorResponse
// @Router       /register [post]
func (h *Handler) Register(c *gin.Context) {
	// Step 1: Decode registration payload.
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(c.Request.Body).Decode(&input); err != nil {
		log.Warn().Err(err).Msg("Failed to decode register request")
		respondError(c, http.StatusBadRequest, "invalid input")
		return
	}

	if input.Email == "" || input.Password == "" {
		respondError(c, http.StatusBadRequest, "email and password required")
		return
	}

	// Step 2: Hash password before persisting user credentials.
	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash password")
		respondError(c, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Step 3: Persist user record and then mint JWT for immediate login.
	user, err := h.store.CreateUser(c.Request.Context(), sqlc.CreateUserParams{
		Email:          input.Email,
		HashedPassword: string(hashed),
	})
	if err != nil {
		log.Error().Err(err).Str("email", input.Email).Msg("Failed to create user")
		respondError(c, http.StatusConflict, "user already exists or failed")
		return
	}

	token, err := GenerateToken(user.ID)
	if err != nil {
		log.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to generate token")
		respondError(c, http.StatusInternalServerError, "failed to generate token")
		return
	}

	log.Info().Str("user_id", user.ID.String()).Str("email", user.Email).Msg("User registered successfully")
	respondJSON(c, http.StatusCreated, RegisterResponse{
		UserID: user.ID.String(),
		Email:  user.Email,
		Token:  token,
	})
}

// Login godoc
// @Summary      Login user
// @Description  Authenticates user with email/password and returns JWT token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body    body      object{email=string,password=string}  true  "User login details"
// @Success      200     {object}  TokenResponse
// @Failure      400     {object}  ErrorResponse
// @Failure      401     {object}  ErrorResponse
// @Failure      500     {object}  ErrorResponse
// @Router       /login [post]
func (h *Handler) Login(c *gin.Context) {
	// Step 1: Decode login payload.
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(c.Request.Body).Decode(&input); err != nil {
		log.Warn().Err(err).Msg("Failed to decode login request")
		respondError(c, http.StatusBadRequest, "invalid input")
		return
	}

	// Step 2: Load user by email and compare bcrypt password hash.
	user, err := h.store.GetUserByEmail(c.Request.Context(), input.Email)
	if err != nil {
		log.Warn().Err(err).Str("email", input.Email).Msg("Login failed - user not found")
		respondError(c, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if compareErr := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(input.Password)); compareErr != nil {
		log.Warn().Str("email", input.Email).Msg("Login failed - invalid password")
		respondError(c, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Step 3: Return a fresh JWT on successful authentication.
	token, err := GenerateToken(user.ID)
	if err != nil {
		log.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to generate token")
		respondError(c, http.StatusInternalServerError, "failed to generate token")
		return
	}

	log.Info().Str("user_id", user.ID.String()).Str("email", user.Email).Msg("User logged in successfully")
	respondJSON(c, http.StatusOK, TokenResponse{Token: token})
}

// CreateAccount godoc
// @Summary      Create a new account
// @Description  Creates a new user-owned account with name and currency
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        body    body      object{name=string}  true  "Account details"
// @Success      201     {object}  AccountResponse
// @Failure      400     {object}  ErrorResponse
// @Failure      401     {object}  ErrorResponse
// @Failure      500     {object}  ErrorResponse
// @Router       /accounts [post]
// @Security     Bearer
func (h *Handler) CreateAccount(c *gin.Context) {
	// Step 1: Authenticate caller from JWT claims.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	// Step 2: Decode request payload.
	var input struct {
		Name string `json:"name"`
	}
	if decodeErr := json.NewDecoder(c.Request.Body).Decode(&input); decodeErr != nil || input.Name == "" {
		respondError(c, http.StatusBadRequest, "name required")
		return
	}

	// Step 3: Create a user-owned account in default currency.
	acc, err := h.store.CreateAccount(c.Request.Context(), sqlc.CreateAccountParams{
		OwnerID:  uuid.NullUUID{UUID: userID, Valid: true},
		Name:     input.Name,
		Currency: "USD",
		IsSystem: false,
	})
	if err != nil {
		log.Error().Err(err).Str("user_id", userID.String()).Str("name", input.Name).Msg("Failed to create account")
		respondError(c, http.StatusInternalServerError, "failed to create account")
		return
	}

	log.Info().Str("account_id", acc.ID.String()).Str("user_id", userID.String()).Str("name", acc.Name).Msg("Account created")
	respondJSON(c, http.StatusCreated, toAccountResponse(acc))
}

// ListAccounts godoc
// @Summary      List user accounts
// @Description  Returns list of accounts owned by authenticated user
// @Tags         accounts
// @Produce      json
// @Success      200     {array}   AccountResponse
// @Failure      401     {object}  ErrorResponse
// @Failure      500     {object}  ErrorResponse
// @Router       /accounts [get]
// @Security     Bearer
func (h *Handler) ListAccounts(c *gin.Context) {
	// Step 1: Authenticate caller.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	// Step 2: Fetch only accounts owned by the authenticated user.
	accounts, err := h.store.ListAccountsByOwner(c.Request.Context(), uuid.NullUUID{UUID: userID, Valid: true})
	if err != nil {
		log.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to list accounts")
		respondError(c, http.StatusInternalServerError, "failed to list accounts")
		return
	}

	response := make([]AccountResponse, len(accounts))
	for i, acc := range accounts {
		response[i] = toAccountResponse(acc)
	}

	respondJSON(c, http.StatusOK, response)
}

// GetAccount godoc
// @Summary      Get account details
// @Description  Returns details of a specific account
// @Tags         accounts
// @Produce      json
// @Param        id   path      string  true  "Account ID"
// @Success      200  {object}  AccountResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /accounts/{id} [get]
// @Security     Bearer
func (h *Handler) GetAccount(c *gin.Context) {
	// Step 1: Authenticate caller and parse target account ID.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	accountIDStr := c.Param("id")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid account ID")
		return
	}

	// Step 2: Enforce account ownership before returning account details.
	acc, err := h.store.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		log.Warn().Err(err).Str("account_id", accountID.String()).Msg("Account not found")
		respondError(c, http.StatusNotFound, "account not found")
		return
	}

	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		log.Warn().Str("account_id", accountID.String()).Str("user_id", userID.String()).Str("owner_id", acc.OwnerID.UUID.String()).Msg("Access denied to account")
		respondError(c, http.StatusForbidden, "access denied")
		return
	}

	respondJSON(c, http.StatusOK, toAccountResponse(acc))
}

// Deposit godoc
// @Summary      Deposit money into account
// @Description  Deposits fiat amount (mock) with double-entry ledger update
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        id      path      string  true   "Account ID"
// @Param        body    body      object{amount=string}  true  "Deposit amount (e.g., 1000.0000)"
// @Success      200     {object}  MessageResponse
// @Failure      400     {object}  ErrorResponse
// @Failure      401     {object}  ErrorResponse
// @Failure      403     {object}  ErrorResponse
// @Failure      404     {object}  ErrorResponse
// @Failure      500     {object}  ErrorResponse
// @Router       /accounts/{id}/deposit [post]
// @Security     Bearer
func (h *Handler) Deposit(c *gin.Context) {
	// Step 1: Authenticate caller and target account.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	accountID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid account ID")
		return
	}

	// Step 2: Load account and enforce ownership authorization.
	acc, err := h.store.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		log.Warn().Err(err).Str("account_id", accountID.String()).Msg("Deposit failed - account not found")
		respondError(c, http.StatusNotFound, "account not found")
		return
	}
	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		log.Warn().Str("account_id", accountID.String()).Str("user_id", userID.String()).Msg("Deposit denied - access forbidden")
		respondError(c, http.StatusForbidden, "access denied")
		return
	}

	// Step 3: Decode amount and invoke service-level double-entry logic.
	amount, err := decodeAmountFromBody(c.Request)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode deposit request")
		respondError(c, http.StatusBadRequest, "invalid input")
		return
	}

	err = h.ledger.Deposit(c.Request.Context(), accountID, amount)
	if err != nil {
		log.Error().Err(err).Str("account_id", accountID.String()).Str("amount", amount).Msg("Deposit failed")
		code := http.StatusInternalServerError
		if errors.Is(err, service.ErrInvalidAmount) || errors.Is(err, service.ErrCurrencyMismatch) {
			code = http.StatusBadRequest
		}
		respondError(c, code, err.Error())
		return
	}

	log.Info().Str("account_id", accountID.String()).Str("user_id", userID.String()).Str("amount", amount).Msg("Deposit successful")
	respondJSON(c, http.StatusOK, MessageResponse{Message: "deposit successful"})
}

// Withdraw godoc
// @Summary      Withdraw money from account
// @Description  Withdraws fiat amount (mock) with double-entry ledger update
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        id      path      string  true   "Account ID"
// @Param        body    body      object{amount=string}  true  "Withdraw amount (e.g., 500.0000)"
// @Success      200     {object}  MessageResponse
// @Failure      400     {object}  ErrorResponse
// @Failure      401     {object}  ErrorResponse
// @Failure      403     {object}  ErrorResponse
// @Failure      404     {object}  ErrorResponse
// @Failure      500     {object}  ErrorResponse
// @Router       /accounts/{id}/withdraw [post]
// @Security     Bearer
func (h *Handler) Withdraw(c *gin.Context) {
	// Step 1: Authenticate caller and target account.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	accountID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid account ID")
		return
	}

	// Step 2: Enforce ownership before attempting withdrawal.
	acc, err := h.store.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		log.Warn().Err(err).Str("account_id", accountID.String()).Msg("Withdrawal failed - account not found")
		respondError(c, http.StatusNotFound, "account not found")
		return
	}
	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		log.Warn().Str("account_id", accountID.String()).Str("user_id", userID.String()).Msg("Withdrawal denied - access forbidden")
		respondError(c, http.StatusForbidden, "access denied")
		return
	}

	// Step 3: Decode amount and delegate business checks to service layer.
	amount, err := decodeAmountFromBody(c.Request)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode withdrawal request")
		respondError(c, http.StatusBadRequest, "invalid input")
		return
	}

	err = h.ledger.Withdraw(c.Request.Context(), accountID, amount)
	if err != nil {
		log.Error().Err(err).Str("account_id", accountID.String()).Str("amount", amount).Msg("Withdrawal failed")
		code := http.StatusInternalServerError
		if errors.Is(err, service.ErrInsufficientFunds) || errors.Is(err, service.ErrInvalidAmount) || errors.Is(err, service.ErrCurrencyMismatch) {
			code = http.StatusBadRequest
		}
		respondError(c, code, err.Error())
		return
	}

	log.Info().Str("account_id", accountID.String()).Str("user_id", userID.String()).Str("amount", amount).Msg("Withdrawal successful")
	respondJSON(c, http.StatusOK, MessageResponse{Message: "withdrawal successful"})
}

// Transfer godoc
// @Summary      Transfer money between accounts
// @Description  Transfers funds between accounts with atomic double-entry updates. The amount field accepts JSON number or string. from_id/to_id are preferred; from_account_id/to_account_id are supported as legacy aliases.
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        body    body      object{from_id=string,to_id=string,amount=string}  true  "Transfer details"
// @Success      200     {object}  MessageResponse
// @Failure      400     {object}  ErrorResponse
// @Failure      401     {object}  ErrorResponse
// @Failure      403     {object}  ErrorResponse
// @Failure      404     {object}  ErrorResponse
// @Router       /transfers [post]
// @Security     Bearer
func (h *Handler) Transfer(c *gin.Context) {
	// Step 1: Authenticate caller.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	// Step 2: Decode payload with support for current and legacy field names.
	var input struct {
		Amount        interface{} `json:"amount"`
		FromID        string      `json:"from_id"`
		ToID          string      `json:"to_id"`
		FromAccountID string      `json:"from_account_id"`
		ToAccountID   string      `json:"to_account_id"`
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.UseNumber()
	if decodeErr := dec.Decode(&input); decodeErr != nil {
		log.Warn().Err(decodeErr).Msg("Failed to decode transfer request")
		respondError(c, http.StatusBadRequest, "invalid input")
		return
	}

	// Normalize IDs so handlers accept both new and legacy API clients.
	fromIDRaw := strings.TrimSpace(input.FromID)
	if fromIDRaw == "" {
		fromIDRaw = strings.TrimSpace(input.FromAccountID)
	}
	toIDRaw := strings.TrimSpace(input.ToID)
	if toIDRaw == "" {
		toIDRaw = strings.TrimSpace(input.ToAccountID)
	}

	log.Info().Str("from_id", fromIDRaw).Str("to_id", toIDRaw).Interface("amount", input.Amount).Msg("Transfer request received")

	if fromIDRaw == "" {
		log.Warn().Msg("Transfer missing from_id")
		respondError(c, http.StatusBadRequest, "from_id (or from_account_id) is required")
		return
	}
	if toIDRaw == "" {
		log.Warn().Msg("Transfer missing to_id")
		respondError(c, http.StatusBadRequest, "to_id (or to_account_id) is required")
		return
	}

	// Step 3: Validate IDs and amount format before business execution.
	fromID, err := uuid.Parse(fromIDRaw)
	if err != nil {
		log.Warn().Err(err).Str("from_id", fromIDRaw).Msg("Invalid from_id UUID format")
		respondError(c, http.StatusBadRequest, "invalid from_id format")
		return
	}

	toID, err := uuid.Parse(toIDRaw)
	if err != nil {
		log.Warn().Err(err).Str("to_id", toIDRaw).Msg("Invalid to_id UUID format")
		respondError(c, http.StatusBadRequest, "invalid to_id format")
		return
	}

	if fromID == uuid.Nil || toID == uuid.Nil {
		respondError(c, http.StatusBadRequest, "from_id and to_id must be valid non-zero UUIDs")
		return
	}

	amount, err := normalizeAmountInput(input.Amount)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse transfer amount")
		respondError(c, http.StatusBadRequest, "invalid input")
		return
	}

	// Step 4: Authorize ownership on source account only.
	fromAcc, err := h.store.GetAccount(c.Request.Context(), fromID)
	if err != nil {
		log.Warn().Err(err).Str("from_id", fromID.String()).Msg("Transfer failed - from account not found")
		respondError(c, http.StatusNotFound, "from account not found")
		return
	}
	if fromAcc.OwnerID.Valid && fromAcc.OwnerID.UUID != userID {
		log.Warn().Str("from_id", fromID.String()).Str("user_id", userID.String()).Msg("Transfer denied - access forbidden")
		respondError(c, http.StatusForbidden, "access denied")
		return
	}

	// Step 5: Run transfer through service layer (atomic double-entry write).
	err = h.ledger.Transfer(c.Request.Context(), fromID, toID, amount)
	if err != nil {
		log.Error().Err(err).Str("from_id", fromID.String()).Str("to_id", toID.String()).Str("amount", amount).Msg("Transfer failed")
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}

	log.Info().Str("from_id", fromID.String()).Str("to_id", toID.String()).Str("user_id", userID.String()).Str("amount", amount).Msg("Transfer successful")
	respondJSON(c, http.StatusOK, MessageResponse{Message: "transfer successful"})
}

// GetEntries godoc
// @Summary      Get account entries
// @Description  Returns list of ledger entries for an account (immutable history)
// @Tags         accounts
// @Produce      json
// @Param        id      path      string  true   "Account ID"
// @Param        limit   query     int     false  "Limit (default 20)"
// @Param        offset  query     int     false  "Offset (default 0)"
// @Success      200     {array}   EntryResponse
// @Failure      400     {object}  ErrorResponse
// @Failure      401     {object}  ErrorResponse
// @Failure      403     {object}  ErrorResponse
// @Failure      404     {object}  ErrorResponse
// @Failure      500     {object}  ErrorResponse
// @Router       /accounts/{id}/entries [get]
// @Security     Bearer
func (h *Handler) GetEntries(c *gin.Context) {
	// Step 1: Authenticate caller and parse account ID.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	accountID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid account ID")
		return
	}

	// Step 2: Enforce account ownership.
	acc, err := h.store.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		log.Warn().Err(err).Str("account_id", accountID.String()).Msg("Get entries failed - account not found")
		respondError(c, http.StatusNotFound, "account not found")
		return
	}
	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		log.Warn().Str("account_id", accountID.String()).Str("user_id", userID.String()).Msg("Get entries denied - access forbidden")
		respondError(c, http.StatusForbidden, "access denied")
		return
	}

	// Step 3: Parse pagination with safe defaults and caps.
	limitStr := c.Query("limit")
	offsetStr := c.Query("offset")

	limit := 20
	offset := 0

	if v, parseErr := strconv.Atoi(limitStr); parseErr == nil && v > 0 {
		limit = min(v, 100)
	}
	if v, parseErr := strconv.Atoi(offsetStr); parseErr == nil && v >= 0 {
		offset = v
	}

	// Validate conversions to int32 to prevent overflow
	if limit > 2147483647 || offset > 2147483647 {
		respondError(c, http.StatusBadRequest, "limit or offset too large")
		return
	}

	// Step 4: Fetch immutable ledger entries for the account.
	entries, err := h.store.ListEntriesByAccount(c.Request.Context(), sqlc.ListEntriesByAccountParams{
		AccountID: accountID,
		Limit:     int32(limit),
		Offset:    int32(offset),
	})
	if err != nil {
		log.Error().Err(err).Str("account_id", accountID.String()).Msg("Failed to fetch entries")
		respondError(c, http.StatusInternalServerError, "failed to fetch entries")
		return
	}

	response := make([]EntryResponse, len(entries))
	for i, entry := range entries {
		response[i] = toEntryResponse(entry)
	}

	respondJSON(c, http.StatusOK, response)
}

// GetTransactions godoc
// @Summary      Get transaction details
// @Description  Returns both entries (debit and credit) for a complete transaction view
// @Tags         accounts
// @Produce      json
// @Param        id   path      string  true  "Transaction ID"
// @Success      200  {array}   EntryResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /transactions/{id} [get]
// @Security     Bearer
func (h *Handler) GetTransactions(c *gin.Context) {
	// Step 1: Authenticate caller and parse transaction ID.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	transactionIDStr := c.Param("id")
	transactionID, err := uuid.Parse(transactionIDStr)
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid transaction ID")
		return
	}

	// Step 2: Load all entries belonging to the transaction.
	entries, err := h.store.ListEntriesByTransaction(c.Request.Context(), transactionID)
	if err != nil {
		log.Error().Err(err).Str("transaction_id", transactionID.String()).Msg("Failed to fetch transaction")
		respondError(c, http.StatusInternalServerError, "failed to fetch transaction")
		return
	}

	if len(entries) == 0 {
		log.Warn().Str("transaction_id", transactionID.String()).Msg("Transaction not found")
		respondError(c, http.StatusNotFound, "transaction not found")
		return
	}

	// Step 3: Authorize if user owns at least one account in this transaction.
	authorized := false
	for _, entry := range entries {
		acc, err := h.store.GetAccount(c.Request.Context(), entry.AccountID)
		if err != nil {
			log.Error().Err(err).Str("account_id", entry.AccountID.String()).Msg("Failed to authorize transaction")
			respondError(c, http.StatusInternalServerError, "failed to authorize transaction")
			return
		}

		if acc.OwnerID.Valid && acc.OwnerID.UUID == userID {
			authorized = true
			break
		}
	}

	if !authorized {
		log.Warn().Str("transaction_id", transactionID.String()).Str("user_id", userID.String()).Msg("Get transaction denied - access forbidden")
		respondError(c, http.StatusForbidden, "access denied")
		return
	}

	response := make([]EntryResponse, len(entries))
	for i, entry := range entries {
		response[i] = toEntryResponse(entry)
	}

	respondJSON(c, http.StatusOK, response)
}

// ReconcileAccount godoc
// @Summary      Reconcile account balance
// @Description  Verifies stored balance matches sum of all ledger entries (credits - debits)
// @Tags         accounts
// @Produce      json
// @Param        id   path      string  true  "Account ID"
// @Success      200  {object}  ReconcileResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /accounts/{id}/reconcile [get]
// @Security     Bearer
func (h *Handler) ReconcileAccount(c *gin.Context) {
	// Step 1: Authenticate caller and parse account ID.
	_, claims, err := FromContext(c)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(c, http.StatusUnauthorized, "invalid token")
		return
	}

	accountID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid account ID")
		return
	}

	// Step 2: Enforce ownership before reconciliation.
	acc, err := h.store.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		log.Warn().Err(err).Str("account_id", accountID.String()).Msg("Reconcile failed - account not found")
		respondError(c, http.StatusNotFound, "account not found")
		return
	}
	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		log.Warn().Str("account_id", accountID.String()).Str("user_id", userID.String()).Msg("Reconcile denied - access forbidden")
		respondError(c, http.StatusForbidden, "access denied")
		return
	}

	// Step 3: Compare stored balance with computed ledger balance.
	matched, err := h.ledger.ReconcileAccount(c.Request.Context(), accountID)
	if err != nil {
		log.Error().Err(err).Str("account_id", accountID.String()).Msg("Reconciliation failed")
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	log.Info().Str("account_id", accountID.String()).Bool("matched", matched).Msg("Reconciliation completed")
	respondJSON(c, http.StatusOK, ReconcileResponse{
		Matched: matched,
		Message: "Account reconciled successfully",
	})
}
