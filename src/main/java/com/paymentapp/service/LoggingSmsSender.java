package com.paymentapp.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Development OTP delivery: logs the OTP instead of sending a real SMS.
 * Replace with a real gateway implementation (Twilio, AWS SNS) in production
 * by providing another {@link SmsSender} bean.
 */
@Slf4j
@Component
public class LoggingSmsSender implements SmsSender {

    @Override
    public void sendOtp(String mobileNumber, String otp) {
        // NEVER log the OTP in production. This is for local development only.
        log.info("[DEV-SMS] Sending OTP {} to mobile {}", otp, mobileNumber);
    }
}

