<#macro emailLayout>
<!doctype html>
<html lang="${locale.language}" dir="${(ltr)?then('ltr','rtl')}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Firefly Identity</title></head>
<body style="margin:0;background:#f3f1eb;color:#272820;font-family:Arial,sans-serif;line-height:1.6;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding:40px 20px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;margin:auto;">
      <tr><td style="padding:0 0 28px;font-size:26px;font-weight:700;letter-spacing:-0.5px;">firefly <span style="color:#855414;">id</span></td></tr>
      <tr><td style="padding:32px;background:#ffffff;border-radius:12px;">
        <#nested>
      </td></tr>
      <tr><td style="padding:24px 0 0;color:#62645b;font-size:13px;">Firefly Identity<br>${msg("ffidEmailPrivacyNotice")}<br>© 2026 Firefly Software Foundation Inc. · <a href="https://www.keycloak.org" style="color:#855414;text-decoration:underline;">${msg("ffidPoweredBy")}</a></td></tr>
    </table>
  </td></tr></table>
</body>
</html>
</#macro>
