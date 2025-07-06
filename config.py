class Config:
    # Google OAuth config
    GOOGLE_CLIENT_ID = "654156985064-vt48t8gj3qod98m4toivp6975lcdojom.apps.googleusercontent.com"
    CLIENT_SECRET = "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"
    REDIRECT_URI = "https://shopifyrenderbot.onrender.com/"
    
    # Azure Blob Storage config
    AZURE_CONNECTION_STRING = (
        "DefaultEndpointsProtocol=https;"
        "AccountName=imagestoragedata;"
        "AccountKey=+2CxrTBgIqQIotfoxH/Af52lK/0qrWma2hSgSZDySzJ9rnRdOnd4cMq1USeBAWVtZQYzy3jKPAoh+ASt09QcOQ==;"
        "EndpointSuffix=core.windows.net"
    )
