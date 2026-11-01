<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section == "header">
    <#if stage == "COMPLETE">${msg("ffidRecoveryCompleteTitle")}<#else>${msg("ffidRecoveryTitle")}</#if>
  <#elseif section == "form">
    <div class="ffid-native-journey">
      <#if messageKey?? && messageKey?has_content>
        <div class="${properties.kcAlertClass!} pf-m-danger" role="alert">
          <span class="ffid-icon ffid-icon--error" aria-hidden="true"></span>
          <span>${msg(messageKey)}</span>
        </div>
      </#if>
      <#if stage == "COMPLETE">
        <p>${msg("ffidRecoveryCompleteInstruction")}</p>
        <a class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}" href="${signInUrl}">${msg("doLogIn")}</a>
        <#if auditRetry!false>
          <form id="ffid-recovery-audit-retry" class="ffid-journey-return" action="${actionUrl}" method="post">
            <input type="hidden" name="csrf" value="${csrf}" />
            <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}" type="submit">${msg("doContinue")}</button>
          </form>
        </#if>
      <#else>
        <p><#if stage == "TOTP">${msg("ffidRecoveryOtpInstruction")}<#else>${msg("ffidRecoveryInstruction")}</#if></p>
        <form id="ffid-native-recovery" class="${properties.kcFormClass!}" action="${actionUrl}" method="post">
          <input type="hidden" name="csrf" value="${csrf}" />
          <#if stage == "PASSWORD">
            <div class="${properties.kcFormGroupClass!}">
              <label class="${properties.kcLabelClass!}" for="username"><#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if></label>
              <span class="${properties.kcInputClass!}"><input id="username" name="username" type="text" autocomplete="username" required autofocus /></span>
            </div>
            <div class="${properties.kcFormGroupClass!}">
              <label class="${properties.kcLabelClass!}" for="password">${msg("password")}</label>
              <span class="${properties.kcInputClass!}"><input id="password" name="password" type="password" autocomplete="current-password" required /></span>
            </div>
          <#elseif stage == "TOTP">
            <div class="${properties.kcFormGroupClass!}">
              <label class="${properties.kcLabelClass!}" for="otp">${msg("ffidRecoveryOtpLabel")}</label>
              <span class="${properties.kcInputClass!}"><input id="otp" name="otp" type="password" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" maxlength="8" required autofocus /></span>
            </div>
          </#if>
          <button id="ffid-recovery-continue" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}" type="submit">${msg("doContinue")}</button>
        </form>
      </#if>
    </div>
  </#if>
</@layout.registrationLayout>
