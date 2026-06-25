from agentguard.providers.notifications.smtp import send_smtp_email


def search_docs(query: str) -> str:
    return f"Mock document search results for: {query}"


def draft_email(to: str, subject: str, body: str) -> str:
    return f"Draft created for {to}. Subject: {subject}. Body: {body}"


def send_email(to: str, subject: str, body: str) -> str:
    result = send_smtp_email(to=to, subject=subject, body=body)
    return f"Email sent to {result['to']} with subject '{result['subject']}'."
