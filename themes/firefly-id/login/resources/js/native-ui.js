for (const element of document.querySelectorAll('time[data-ffid-local-date]')) {
  const date = new Date(element.dateTime);
  if (Number.isNaN(date.getTime())) continue;
  try {
    element.textContent = new Intl.DateTimeFormat(document.documentElement.lang || undefined,
      { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  } catch { /* The server-rendered ISO date remains readable without locale support. */ }
}
