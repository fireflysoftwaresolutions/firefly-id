<#macro content>
  <footer class="ffid-footer" aria-label="${msg('ffidFooterLabel')}">
    <span>${msg('ffidProductName')}</span>
    <span>${msg('ffidFooterDescription')}</span>
    <span>${msg('ffidCopyright')} · <a href="https://www.keycloak.org">${msg('ffidPoweredBy')}</a></span>
    <#if (properties.nativeRecoveryEnabled!"false") == "true" && (pageId!"") == "login" && url.loginUrl?? && url.loginUrl?contains("/login-actions/")>
      <a class="ffid-recovery-entry" href="${url.loginUrl?keep_before('/login-actions/')}/firefly-recovery">${msg("ffidRecoveryTitle")}</a>
    </#if>
    <#if realm.internationalizationEnabled && locale.supported?size gt 1>
      <select
        class="ffid-locale-selector"
        aria-label="${msg("languages")}"
        id="login-select-toggle"
        onchange="if (this.value) window.location.href=this.value"
      >
        <#list locale.supported?sort_by("label") as l>
          <option
            value="${l.url}"
            ${(l.languageTag == locale.currentLanguageTag)?then('selected','')}
          >
            ${l.label}
          </option>
        </#list>
      </select>
    </#if>
  </footer>
</#macro>
