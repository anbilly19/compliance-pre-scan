# Install spaCy language models required for bilingual PII scanning
# Run once after `uv sync`

Write-Host "Installing spaCy models for EN + DE..." -ForegroundColor Cyan

uv run python -m spacy download en_core_web_md
uv run python -m spacy download de_core_news_md

Write-Host "Done. Both models installed." -ForegroundColor Green
