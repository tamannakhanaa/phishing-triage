#!/bin/bash

# Trap to kill background processes on exit
trap "echo 'Stopping services...' && kill $BACKEND_PID 2>/dev/null && echo 'Services stopped.'" EXIT

# Function to check if a port is in use and kill the process
kill_if_port_in_use() {
  PORT=$1
  PID=$(lsof -ti:$PORT)
  if [ -n "$PID" ]; then
    echo "Port $PORT is already in use.\nKilling process on port $PORT..."
    kill -9 $PID 2>/dev/null
    sleep 1 # Give it a moment to release the port
  fi
}

# Kill any existing processes on port 8001 (backend)
kill_if_port_in_use 8001

# Activate virtual environment if it exists
if [ -f ".venv/bin/activate" ]; then
  echo "Activating virtual environment from project root..."
  source .venv/bin/activate
else
  echo "Warning: Virtual environment not found. Please run 'python3 -m venv .venv && source .venv/bin/activate && pip install -r backend/requirements.txt'"
fi

# Load environment variables
if [ -f ".env" ]; then
  echo "Loading environment variables from .env..."
  source .env
else
  echo "Warning: .env file not found. Ensure environment variables are set."
fi

# Start backend server
echo "🚀 Starting backend API server on http://localhost:8001..."
python3 -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8001 --app-dir . & # Run in background
BACKEND_PID=$!

echo "⏳ Waiting for backend to start..."
# Give the backend server a moment to start up and check its health endpoint
sleep 5 # Give it more time

if curl -s http://localhost:8001/health > /dev/null; then
  echo "✅ Backend API is running! API docs available at http://localhost:8001/docs"
else
  echo "❌ Backend API failed to start. Check backend_server.log for details."
  # For debugging, you might want to uncomment the following line to see logs
  # tail -n 50 backend_server.log
  exit 1
fi

# Print access information
echo ""
echo "🎉 Phishing Triage System is now running!"
echo "📊 Access the system at:"
echo "   - 💻 Frontend UI: http://localhost:8001/"
echo "   - ⚙️ Backend API: http://localhost:8001/docs"
echo "   - 📈 MLflow Dashboard: http://localhost:5000 (if integrated and running separately)"
echo ""
echo "Press Ctrl+C to stop all services."

wait $BACKEND_PID # Keep the script running until background processes are killed
