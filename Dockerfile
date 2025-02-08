# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . /app/

# Expose the port your app will run on
EXPOSE 8000

# Set environment variable
ENV PYTHONUNBUFFERED 1

# Command to run the application
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
