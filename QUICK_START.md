# Quick Start - Chrome Extension

## Install in 3 Steps

1. **Open Chrome Extensions**
   ```
   Navigate to: chrome://extensions/
   ```

2. **Enable Developer Mode**
   - Toggle switch in top-right corner

3. **Load Extension**
   - Click "Load unpacked"
   - Select `extension/` folder
   - Done!

## Test It

1. **Visit any website** - it will be analyzed automatically
2. **Click extension icon** - see the analysis results
3. **Try suspicious patterns** - URLs with keywords like "paypal-verify.tk" will trigger warnings

## What to Expect

- **Safe sites**: Brief green badge, no warnings
- **Suspicious sites**: Full-screen warning with reasons
- **Popup**: Shows confidence score and detected features

## Files Overview

```
extension/
├── manifest.json          ← Extension config
├── popup.html            ← UI when you click icon
├── js/
│   ├── url-features.js   ← Extract 39 features
│   ├── ml-model.js       ← Run Random Forest
│   ├── background.js     ← Monitor URLs
│   ├── content.js        ← Show warnings
│   └── popup.js          ← Popup logic
└── models/
    └── model_lite.json   ← 30-tree ML model
```

## Troubleshooting

**Extension not working?**
- Check browser console (F12) for errors
- Verify `models/model_lite.json` exists
- Try refreshing the extension

**No warnings showing?**
- Only high-confidence phishing (≥70%) triggers warnings
- Some sites may have been dismissed (24hr cooldown)
- Check popup for current analysis

## Questions?

See `CHROME_EXTENSION_SUMMARY.md` for complete details!
