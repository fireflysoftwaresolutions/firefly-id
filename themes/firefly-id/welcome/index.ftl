<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Firefly Identity</title>
  <link rel="icon" type="image/svg+xml" href="${resourcesPath}/img/favicon.svg">
  <link rel="stylesheet" href="${resourcesPath}/css/welcome.css">
</head>
<body>
  <main>
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="${resourcesPath}/img/wordmark-dark.svg">
      <img src="${resourcesPath}/img/wordmark-light.svg" alt="Firefly Identity" width="265" height="48">
    </picture>
    <h1>Identity and access,<br>connected.</h1>
    <p>Your applications connect you to the right sign-in experience. Open your application to continue.</p>
    <#if adminConsoleEnabled>
      <a href="${adminUrl}">Open administration</a>
    </#if>
    <footer>© 2026 Firefly Software Foundation Inc.</footer>
  </main>
</body>
</html>
