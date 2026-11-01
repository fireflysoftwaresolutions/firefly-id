<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Firefly Identity</title>
  <link rel="icon" type="image/svg+xml" href="${resourcesPath}/img/favicon.svg">
  <link rel="stylesheet" href="${resourcesPath}/css/firefly-tokens.css">
  <link rel="stylesheet" href="${resourcesPath}/css/welcome.css">
  <script src="${resourcesPath}/js/welcome-locale.js" defer></script>
</head>
<body>
  <main>
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="${resourcesPath}/img/wordmark-dark.svg">
      <img src="${resourcesPath}/img/wordmark-light.svg" alt="Firefly Identity" width="265" height="48">
    </picture>
    <h1><span data-ffid-es="Identidad y acceso,">Identity and access,</span><br><span data-ffid-es="conectados.">connected.</span></h1>
    <p data-ffid-es="Tus aplicaciones te llevan al inicio de sesión adecuado. Abre tu aplicación para continuar.">Your applications connect you to the right sign-in experience. Open your application to continue.</p>
    <#if adminConsoleEnabled>
      <a href="${adminUrl}" data-ffid-es="Abrir administración">Open administration</a>
    </#if>
    <footer>© 2026 Firefly Software Foundation Inc. · <a href="https://www.keycloak.org" data-ffid-es="Con tecnología de Keycloak">Powered by Keycloak</a></footer>
  </main>
</body>
</html>
