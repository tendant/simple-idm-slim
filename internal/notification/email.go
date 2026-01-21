package notification

import (
	"fmt"
	"net/smtp"
)

type EmailConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	FromName string
}

type EmailService struct {
	config EmailConfig
}

func NewEmailService(config EmailConfig) *EmailService {
	return &EmailService{config: config}
}

func (s *EmailService) SendVerificationEmail(to, verifyURL string) error {
	subject := "Verify Your Email Address"
	body := fmt.Sprintf(`<html><body>
		<h2>Verify Your Email Address</h2>
		<p>Thank you for registering! Please verify your email address to complete your registration.</p>
		<p><a href="%s">Click here to verify your email</a></p>
		<p>Or copy this link to your browser: %s</p>
		<p>This link will expire in 24 hours.</p>
	</body></html>`, verifyURL, verifyURL)
	return s.sendEmail(to, subject, body)
}

func (s *EmailService) SendPasswordResetEmail(to, resetURL string) error {
	subject := "Reset Your Password"
	body := fmt.Sprintf(`<html><body>
		<h2>Reset Your Password</h2>
		<p>A password reset has been requested for your account.</p>
		<p><a href="%s">Click here to reset your password</a></p>
		<p>Or copy this link to your browser: %s</p>
		<p>This link will expire in 1 hour.</p>
		<p>If you did not request this password reset, please ignore this email.</p>
	</body></html>`, resetURL, resetURL)
	return s.sendEmail(to, subject, body)
}

func (s *EmailService) sendEmail(to, subject, body string) error {
	from := s.config.From
	if s.config.FromName != "" {
		from = fmt.Sprintf("%s <%s>", s.config.FromName, s.config.From)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, subject, body)

	auth := smtp.PlainAuth("", s.config.User, s.config.Password, s.config.Host)
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	return smtp.SendMail(addr, auth, s.config.From, []string{to}, []byte(msg))
}
