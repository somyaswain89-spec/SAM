import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { PageHeader, Panel } from '../components/Panel';

type Answer = { answer: string; mode: string; sources: string[]; generatedAt: string; scope: string; warning?: string | null };
type AnalystStatus = { aiAnalystConfigured: boolean };
const starterQuestions = ['How do I request an approved rescan?', 'Which findings are highest priority?', 'What assets have low compliance?', 'What evidence confirms a website is behind a WAF?'];

export function AnalystPage() {
  const [question, setQuestion] = useState('');
  const [history, setHistory] = useState<Array<{ question: string; answer: Answer }>>([]);
  const status = useQuery({ queryKey: ['integration-status'], queryFn: () => api.get<AnalystStatus>('/integrations/status') });
  const ask = useMutation({
    mutationFn: (input: { question: string; history: Array<{ role: 'user' | 'assistant'; content: string }> }) => api.post<Answer>('/analyst/ask', input),
    onSuccess: (answer, submitted) => { setHistory((current) => [...current, { question: submitted.question, answer }]); setQuestion(''); },
  });
  function submit(event: React.FormEvent) {
    event.preventDefault();
    const submittedQuestion = question.trim();
    if (!submittedQuestion) return;
    const priorTurns = history.slice(-4).flatMap((item) => [
      { role: 'user' as const, content: item.question },
      { role: 'assistant' as const, content: item.answer.answer },
    ]);
    ask.mutate({ question: submittedQuestion, history: priorTurns });
  }
  return <>
    <PageHeader title="AI security analyst" description="Ask in natural language about assets, vulnerabilities, remediation, compliance and response workflows. Each answer shows whether it used the configured AI provider or SAM's limited rule-based guidance." />
    <Panel title="Ask about your SAM data">
      {!status.isPending && !status.error && <div className="notice">Analyst mode: {status.data.aiAnalystConfigured ? 'AI provider enabled; bounded SAM security data is sent to the configured provider.' : 'rule-based QA; configure the provider and explicitly approve data sharing to enable AI answers.'}</div>}
      <div className="question-chips">{starterQuestions.map((prompt) => <button key={prompt} className="secondary" onClick={() => setQuestion(prompt)}>{prompt}</button>)}</div>
      <form className="ask-form" onSubmit={submit}><textarea value={question} onChange={(event) => setQuestion(event.target.value)} maxLength={1000} required placeholder="Ask about a specific asset, finding, rescan, remediation, WAF posture, zero-day signal, compliance, or containment…" /><button className="primary" disabled={ask.isPending || !question.trim()}>{ask.isPending ? 'Reviewing SAM records…' : 'Ask analyst'}</button></form>
      {ask.error && <div className="notice error" role="alert">{ask.error.message}</div>}
      {history.length === 0 && <div className="empty">Ask a question to receive a response from persisted SAM records.</div>}
      <div className="conversation">{history.map((item, index) => <article className="answer-card" key={`${index}-${item.answer.generatedAt}`}><b>You</b><p>{item.question}</p><b>SAM analyst · {item.answer.mode}</b><p>{item.answer.answer}</p>{item.answer.warning && <div className="notice" role="status">{item.answer.warning}</div>}<small>Sources: {item.answer.sources.join(', ')} · Scope: {item.answer.scope}</small></article>)}</div>
    </Panel>
  </>;
}
