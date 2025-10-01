# Configuration Guide

## Environment Variables

The application uses environment variables stored in `.env` file for configuration.

### Required Configuration

1. **Gemini API Key** - For AI-powered malware analysis
   - Variable: `GEMINI_API_KEY`
   - Get your key from: https://makersuite.google.com/app/apikey
   - Replace the value in `.env` file with your actual API key

### Optional Configuration

- `FLASK_ENV`: Set to `development` or `production`
- `FLASK_DEBUG`: Enable/disable debug mode
- `DEFAULT_TIMEOUT`: Default analysis timeout in seconds
- `MAX_TIMEOUT`: Maximum allowed timeout in seconds

## Security Notes

- The `.env` file is already added to `.gitignore` to prevent accidental commit of API keys
- Never commit API keys or secrets to version control
- Keep your Gemini API key secure and rotate it regularly