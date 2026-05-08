"""ai_audit.integrations — Drop-in adapters for popular frameworks.

Each submodule has its own optional dependency and is imported lazily.
Importing ``ai_audit.integrations`` itself does NOT import any optional dep.

Available adapters:
    ai_audit.integrations.fastapi      requires: fastapi, starlette
    ai_audit.integrations.langchain    requires: langchain-core
    ai_audit.integrations.openai       requires: openai>=1.0
    ai_audit.integrations.anthropic    requires: anthropic>=0.20
"""
