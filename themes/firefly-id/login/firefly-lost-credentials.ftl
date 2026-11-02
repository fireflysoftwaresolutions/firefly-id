<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section == "header">
    <#if stage == "COMPLETE">${msg("ffidLostCompleteTitle")}<#else>${msg("ffidLostTitle")}</#if>
  <#elseif section == "form">
    <div class="ffid-native-journey" data-stage="${stage}">
      <#if messageKey?? && messageKey?has_content>
        <div class="${properties.kcAlertClass!} pf-m-danger" role="alert">
          <span class="ffid-icon ffid-icon--error" aria-hidden="true"></span><span>${msg(messageKey)}</span>
        </div>
      </#if>
      <#if stage == "COMPLETE">
        <p>${msg("ffidLostCompleteInstruction")}</p>
        <a class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}" href="${signInUrl}">${msg("doLogIn")}</a>
      <#else>
        <p><#if stage == "VERIFY">${msg("ffidLostVerifyInstruction")}<#elseif stage == "ENROLL">${msg("ffidLostEnrollInstruction")}<#else>${msg("ffidLostIdentifyInstruction")}</#if></p>
      </#if>
      <#if stage != "COMPLETE" || recordPending!false>
      <form id="ffid-lost-credentials" class="${properties.kcFormClass!}" action="${actionUrl}" method="post">
        <input type="hidden" name="csrf" value="${csrf}" />
        <#if stage == "IDENTIFY">
          <div class="${properties.kcFormGroupClass!}">
            <label class="${properties.kcLabelClass!}" for="username">${msg("usernameOrEmail")}</label>
            <span class="${properties.kcInputClass!}"><input id="username" name="username" type="text" maxlength="254" autocomplete="username" required autofocus /></span>
          </div>
        <#elseif stage == "VERIFY">
          <#if verificationUrl?? && verificationUrl?has_content>
            <a id="ffid-lost-provider" class="ffid-journey-return" href="${verificationUrl}" target="_blank" rel="noopener noreferrer">${msg("ffidLostOpenProvider")}</a>
          </#if>
          <p>${msg("ffidLostProviderReturn")}</p>
        <#elseif stage == "ENROLL">
          <div class="${properties.kcFormGroupClass!}">
            <label class="${properties.kcLabelClass!}" for="password">${msg("passwordNew")}</label>
            <span class="${properties.kcInputClass!}"><input id="password" name="password" type="password" maxlength="1024"<#if passwordMinimum??> minlength="${passwordMinimum?c}" aria-describedby="ffid-lost-password-help"</#if> autocomplete="new-password" required autofocus /></span>
            <#if passwordMinimum??><p id="ffid-lost-password-help">${msg("ffidLostPasswordMinimum", passwordMinimum)}</p></#if>
          </div>
          <div class="${properties.kcFormGroupClass!}">
            <label class="${properties.kcLabelClass!}" for="passwordConfirm">${msg("passwordConfirm")}</label>
            <span class="${properties.kcInputClass!}"><input id="passwordConfirm" name="passwordConfirm" type="password" maxlength="1024" autocomplete="new-password" required /></span>
          </div>
          <div class="${properties.kcFormGroupClass!}">
            <label class="${properties.kcLabelClass!}" for="ffid-lost-enrollment-secret">${msg("ffidLostSetupKey")}</label>
            <output id="ffid-lost-enrollment-secret" class="ffid-enrollment-secret" aria-describedby="ffid-lost-otp-help">${enrollmentSecret?replace("(.{4})", "$1 ", "r")?trim}</output>
            <p id="ffid-lost-otp-help">${msg("ffidLostSetupInstruction", otpAlgorithm, otpDigits, otpPeriod)}</p>
            <label class="${properties.kcLabelClass!}" for="otp">${msg("ffidLostOtpLabel")}</label>
            <span class="${properties.kcInputClass!}"><input id="otp" name="otp" type="password" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" maxlength="8" aria-describedby="ffid-lost-otp-help" required /></span>
          </div>
        </#if>
        <button id="ffid-lost-continue" class="${properties.kcButtonClass!} <#if stage == 'COMPLETE'>${properties.kcButtonSecondaryClass!}<#else>${properties.kcButtonPrimaryClass!}</#if> ${properties.kcButtonBlockClass!}" type="submit"><#if stage == "VERIFY">${msg("ffidLostVerifyContinue")}<#elseif stage == "ENROLL">${msg("ffidLostReplace")}<#elseif stage == "COMPLETE">${msg("ffidLostFinishRequest")}<#else>${msg("doContinue")}</#if></button>
      </form>
      </#if>
      <#if stage != "COMPLETE"><a class="ffid-journey-return" href="${signInUrl}">${msg("ffidRecoveryBackToSignIn")}</a></#if>
    </div>
  </#if>
</@layout.registrationLayout>
