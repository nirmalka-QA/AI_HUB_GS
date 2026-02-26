package src.authentication

/**
 * Multi-Channel Authentication with MFA and Secure OTP Lifecycle
 * This class handles the authentication process using email or mobile number,
 * implements MFA with OTP lifecycle management, and ensures compliance with security standards.
 */

class MultiChannelAuthentication {

  /**
   * Validates the email address format based on RFC 5322.
   * @param email The email address provided by the user.
   * @return true if the email format is valid, false otherwise.
   */
  function validateEmail(email: String): Boolean {
    // Regex for RFC 5322 email validation
    var emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    return email.matches(emailRegex)
  }

  /**
   * Handles primary authentication.
   * @param credentials The user's credentials.
   * @return true if authentication is successful, false otherwise.
   */
  function primaryAuthentication(credentials: Credentials): Boolean {
    // Simulate primary authentication logic
    return credentials.isValid()
  }

  /**
   * Triggers OTP challenge for MFA.
   * @param user The user object.
   * @param channel The MFA channel (email or mobile).
   * @return The generated OTP.
   */
  function triggerOTPChallenge(user: User, channel: String): String {
    // Generate and send OTP based on the channel
    var otp = generateOTP()
    sendOTP(user, channel, otp)
    return otp
  }

  /**
   * Validates the OTP entered by the user.
   * @param user The user object.
   * @param otp The OTP entered by the user.
   * @return true if the OTP is valid, false otherwise.
   */
  function validateOTP(user: User, otp: String): Boolean {
    // Check if OTP is valid and within TTL
    return user.isOTPValid(otp)
  }

  /**
   * Locks the user's account after consecutive failed OTP attempts.
   * @param user The user object.
   */
  function lockAccount(user: User): void {
    user.lock()
  }

  /**
   * Disables OTP resend option for 60 seconds.
   * @param user The user object.
   */
  function disableResendOTP(user: User): void {
    user.setResendOTPDisabled(true, 60)
  }

  /**
   * Prevents OTP reuse.
   * @param user The user object.
   * @param otp The OTP entered by the user.
   * @return true if OTP is reused, false otherwise.
   */
  function preventOTPReuse(user: User, otp: String): Boolean {
    return user.hasUsedOTP(otp)
  }

  /**
   * Enforces password complexity during registration.
   * @param password The password provided by the user.
   * @param username The username of the user.
   * @param email The email address of the user.
   * @return true if the password meets complexity requirements, false otherwise.
   */
  function enforcePasswordComplexity(password: String, username: String, email: String): Boolean {
    // Check password length and complexity
    var complexityRegex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$"
    if (!password.matches(complexityRegex)) {
      return false
    }

    // Ensure password does not contain username or email
    if (password.contains(username) || password.contains(email)) {
      return false
    }

    return true
  }

  /**
   * Generates a secure OTP.
   * @return The generated OTP.
   */
  private function generateOTP(): String {
    // Simulate OTP generation logic
    return "123456" // Replace with secure generation logic
  }

  /**
   * Sends OTP to the user via the specified channel.
   * @param user The user object.
   * @param channel The MFA channel (email or mobile).
   * @param otp The OTP to send.
   */
  private function sendOTP(user: User, channel: String, otp: String): void {
    // Simulate sending OTP logic
    user.notify(channel, "Your OTP is: " + otp)
  }
}