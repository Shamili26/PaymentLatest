package com.paymentapp.controller;

import com.paymentapp.dto.Auth;
import com.paymentapp.service.AuthService;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // ─── POST /api/auth/register ──────────────────────────────────────────────

    @PostMapping("/register")
    public ResponseEntity<Auth.AuthResponse> register(
            @Valid @RequestBody Auth.RegisterRequest request
    ) {
        Auth.AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ─── POST /api/auth/login ─────────────────────────────────────────────────

    @PostMapping("/login")
    public ResponseEntity<Auth.AuthResponse> login(
            @Valid @RequestBody Auth.LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        String ipAddress  = getClientIp(httpRequest);
        String userAgent  = httpRequest.getHeader("User-Agent");

        Auth.AuthResponse response = authService.login(request, ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    // ─── Exception handlers ───────────────────────────────────────────────────

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Auth.ApiError> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining("; "));
        return ResponseEntity
                .badRequest()
                .body(new Auth.ApiError(400, "Validation Failed", message));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Auth.ApiError> handleConflict(IllegalArgumentException ex) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(new Auth.ApiError(409, "Conflict", ex.getMessage()));
    }

    @ExceptionHandler({BadCredentialsException.class, UsernameNotFoundException.class})
    public ResponseEntity<Auth.ApiError> handleBadCredentials() {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new Auth.ApiError(401, "Unauthorized", "Invalid username or password"));
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<Auth.ApiError> handleDisabled() {
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(new Auth.ApiError(403, "Forbidden", "Account is disabled"));
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<Auth.ApiError> handleLocked() {
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(new Auth.ApiError(403, "Forbidden", "Account is locked"));
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
