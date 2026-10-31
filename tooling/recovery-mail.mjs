export function selectNewRecoveryMessage(messages, previousIds, recipient) {
  return messages.find(message => !previousIds.has(message.ID)
    && message.To?.some(to => to.Address === recipient));
}
