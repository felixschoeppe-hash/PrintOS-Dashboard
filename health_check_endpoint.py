# Health check endpoint für Render.com
# Füge das ans Ende von backend/server.py hinzu:

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test MongoDB connection
        await db.command("ping")
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail="Database unavailable")
