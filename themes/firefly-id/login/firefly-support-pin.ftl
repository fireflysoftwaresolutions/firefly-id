<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section == "header">
    <#if stage == "REVOKE">${msg("ffidPinRevokeTitle")}<#else>${msg("ffidPinTitle")}</#if>
  <#elseif section == "form">
    <div class="ffid-native-journey">
      <#if messageKey?? && messageKey?has_content>
        <div class="${properties.kcAlertClass!} pf-m-danger" role="alert">
          <span class="ffid-icon ffid-icon--error" aria-hidden="true"></span>
          <span>${msg(messageKey)}</span>
        </div>
      </#if>
      <#if stage == "SET" || stage == "REVOKE">
        <p id="ffid-pin-instruction"><#if stage == "REVOKE">${msg("ffidPinRevokeInstruction")}<#else>${msg("ffidPinInstruction")}</#if></p>
        <form id="ffid-support-pin" class="${properties.kcFormClass!}" action="${actionUrl}" method="post">
          <input type="hidden" name="csrf" value="${csrf}" />
          <div class="${properties.kcFormGroupClass!}">
            <label class="${properties.kcLabelClass!}" for="password">${msg("password")}</label>
            <span class="${properties.kcInputClass!}"><input id="password" name="password" type="password" autocomplete="current-password" required autofocus /></span>
          </div>
          <div class="${properties.kcFormGroupClass!}">
            <label class="${properties.kcLabelClass!}" for="otp">${msg("ffidRecoveryOtpLabel")}</label>
            <span class="${properties.kcInputClass!}"><input id="otp" name="otp" type="password" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" maxlength="8" required /></span>
          </div>
          <#if stage == "SET">
          <div class="${properties.kcFormGroupClass!}">
            <label class="${properties.kcLabelClass!}" for="pin">${msg("ffidPinLabel")}</label>
            <span class="${properties.kcInputClass!}"><input id="pin" name="pin" type="password" inputmode="numeric" autocomplete="new-password" pattern="[0-9]{8}" minlength="8" maxlength="8" aria-describedby="ffid-pin-instruction" required /></span>
          </div>
          <div class="${properties.kcFormGroupClass!}">
            <label class="${properties.kcLabelClass!}" for="pinConfirm">${msg("ffidPinConfirmLabel")}</label>
            <span class="${properties.kcInputClass!}"><input id="pinConfirm" name="pinConfirm" type="password" inputmode="numeric" autocomplete="new-password" pattern="[0-9]{8}" minlength="8" maxlength="8" required /></span>
          </div>
          </#if>
          <button id="ffid-pin-save" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}" type="submit"><#if stage == "REVOKE">${msg("ffidPinRevoke")}<#else>${msg("ffidPinSave")}</#if></button>
        </form>
      <#else>
        <p>${msg("ffidPinStatusInstruction")}</p>
        <dl class="ffid-credential-status">
          <div><dt>${msg("ffidPinStatusLabel")}</dt><dd><#if (pinStatus!"ABSENT") == "ACTIVE">${msg("ffidPinActive")}<#elseif (pinStatus!"ABSENT") == "LOCKED">${msg("ffidPinLocked")}<#else>${msg("ffidPinAbsent")}</#if></dd></div>
          <#if replacedAt?? && replacedAt?has_content><div><dt>${msg("ffidPinReplacedLabel")}</dt><dd><time datetime="${replacedAt}" data-ffid-local-date>${replacedAt}</time></dd></div></#if>
        </dl>
        <a class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}" href="${actionUrl}">${msg("ffidPinReplace")}</a>
        <#if revokeUrl?? && (pinStatus!"ABSENT") != "ABSENT"><a class="ffid-journey-return" href="${revokeUrl}">${msg("ffidPinRevoke")}</a></#if>
      </#if>
      <#if accountUrl??><a class="ffid-journey-return" href="${accountUrl}">${msg("ffidBackToAccount")}</a></#if>
    </div>
    <script type="module" src="${url.resourcesPath}/js/native-ui.js"></script>
  </#if>
</@layout.registrationLayout>
