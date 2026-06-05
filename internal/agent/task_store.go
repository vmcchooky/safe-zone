package agent

func (t *AlertTask) AgentEventStore() agentEventStore {
	return t.store
}

func (t *AuditTask) AgentEventStore() agentEventStore {
	return t.store
}

func (t *FeedSyncTask) AgentEventStore() agentEventStore {
	return t.store
}

func (t *OSINTTask) AgentEventStore() agentEventStore {
	return t.store
}

func (t *WhitelistUpdateTask) AgentEventStore() agentEventStore {
	return t.store
}
