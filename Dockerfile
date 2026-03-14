# Use the official, lightweight Python 3.10 Linux image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy all project files into the container
COPY . /app

# Install the dependencies defined in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8501, which Streamlit uses
EXPOSE 8501

# Command to run the application
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
