# Hero2Tech - Currency Conversion API

Hero2Tech is a Currency Conversion API that allows users to convert currency rates, retrieve the latest rates, and convert from one base currency to multiple target currencies. It includes features such as user signup, login, password reset, API key management, dark and light modes, and comprehensive API documentation.

## Features

- **Currency Conversion**: Convert from one currency to another.
- **Latest Rates**: Fetch the latest currency exchange rates.
- **Base Currency Conversion**: Convert from a base currency to multiple target currencies.
- **User Authentication**: Signup, login, and password reset functionality.
- **API Key Management**: Users can generate, delete, and regenerate API keys (up to 3 keys per user).
- **Themes**: Dark and Light modes.
- **Google OAuth2 Authentication**: Login using Google account.
- **hCaptcha Integration**: For additional security in forms.
- **API Documentation**: Detailed API usage instructions.

## Getting Started

### Prerequisites

- **Python 3.10.15**: This project has been tested with Python 3.10.15.
- **MySQL Database**: Set up a MySQL database for the application.
- **Google Cloud Account**: You will need a Google Cloud account to enable OAuth2 and retrieve the Google Client ID and Client Secret.
- **hCaptcha Account**: Set up an hCaptcha account to get the Site Key and Secret Key.

### Setup

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Techy-Haroon/Hero2Tech-Currency-Conversion-API.git
   cd Hero2Tech-Currency-Conversion-API
   ```

2. **Create a Virtual Environment**:

   ```bash
   python3 -m venv venv
   ```

3. **Activate the Virtual Environment**:

   - On Windows:
     ```bash
     .\venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

4. **Install Dependencies**:
   Run the following command to install the required libraries:

   ```bash
   cd src
   pip install -r requirements.txt
   ```

5. **Set up the Environment Variables**:
   Create a `.env` file in the src directory and add the following environment variables:

   ```env
   SECRET_KEY= "A Strong Secret Key"
   SQLALCHEMY_DATABASE_URI='mysql://username:password@localhost/database'
   MAIL_SERVER=Your Mail Server
   MAIL_PORT=Port
   MAIL_USE_TLS=True
   MAIL_USERNAME=username
   MAIL_PASSWORD=Your Mail Server Password
   PERMANENT_SESSION_LIFETIME_HOURS=24
   SESSION_COOKIE_SECURE=True
   SESSION_COOKIE_HTTPONLY=True
   REMEMBER_COOKIE_SECURE=True
   REMEMBER_COOKIE_HTTPONLY=True
   DEBUG=False
   TESTING=False
   GOOGLE_CLIENT_ID=Your Google Client ID
   GOOGLE_CLIENT_SECRET=Your Google Client Secret
   HCAPTCHA_SITE_KEY=Your HCaptcha Site Key
   HCAPTCHA_SECRET_KEY=Your HCaptcha Secret Key
   LOGGING_LEVEL=INFO
   ```

### Explanation of `.env` Variables

- **SECRET_KEY**: A strong secret key used to secure sessions. You can generate one using a tool like `secrets.token_hex(16)`.
- **SQLALCHEMY_DATABASE_URI**: The URI to connect to your MySQL database. Replace `username`, `password`, and `database` with your actual MySQL credentials.
- **MAIL_SERVER**: Your email server address (e.g., `smtp.gmail.com`).
- **MAIL_PORT**: The port used by your email server (usually 25, 587, or 465).
- **MAIL_USERNAME** and **MAIL_PASSWORD**: Your email credentials.
- **PERMANENT_SESSION_LIFETIME_HOURS**: The time (in hours) a session remains valid (default is 24).
- **SESSION_COOKIE_SECURE**, **SESSION_COOKIE_HTTPONLY**, **REMEMBER_COOKIE_SECURE**, **REMEMBER_COOKIE_HTTPONLY**: These settings ensure that your cookies are secure and not accessible via JavaScript.
- **FORCE_HTTPS**: This is setting whether you want to force HTTPS in your app or not. You should ideally set it to False on Development server but True on Production Server. You can set it to True on Development server only if you have certificate on it. Otherwise, you will get error on loading page and it won't work.
- **DEBUG** and **TESTING**: These settings control whether the application runs in debugging or testing mode.
- **GOOGLE_CLIENT_ID** and **GOOGLE_CLIENT_SECRET**: The credentials obtained from Google Cloud for OAuth2 login.
- **HCAPTCHA_SITE_KEY** and **HCAPTCHA_SECRET_KEY**: Your hCaptcha credentials for form security.
- **LOGGING_LEVEL**: The logging level, typically set to `INFO` or `DEBUG`.

### Getting Google Client ID and Client Secret

To integrate Google OAuth2 into your app, you need to set up OAuth2 in Google Cloud. Here’s how:

1. Go to the **[Google Cloud Console](https://console.cloud.google.com/)**.
2. Create a new project or select an existing one.
3. Navigate to **APIs & Services > Credentials**.
4. Click **Create Credentials** and select **OAuth 2.0 Client IDs**.
5. Configure the consent screen by following the prompts (you can choose "External" as the user type).
6. After setting up, you’ll get the **Google Client ID** and **Google Client Secret**. Copy these values and add them to your `.env` file:
   ```env
   GOOGLE_CLIENT_ID=Your Google Client ID
   GOOGLE_CLIENT_SECRET=Your Google Client Secret
   ```

### Getting hCaptcha Site Key and Secret Key

To add hCaptcha for form security, follow these steps:

1. Visit the **[hCaptcha website](https://www.hcaptcha.com/)** and sign up or log in.
2. Create a new site to get your **Site Key** and **Secret Key**.
3. Copy these keys and add them to your `.env` file:
   ```env
   HCAPTCHA_SITE_KEY=Your HCaptcha Site Key
   HCAPTCHA_SECRET_KEY=Your HCaptcha Secret Key
   ```

### Setting Up the Database

The SQL file to set up your database is located in the `db/` folder of this project. To set up your database, follow these steps:

1. Locate the `db/` folder in the project directory.
2. Inside this folder, you’ll find the SQL file (e.g., `database_schema.sql`). This file contains all the necessary SQL commands to set up the required tables and relationships.
3. Import this SQL file into your MySQL database using the following command:
   ```bash
   mysql -u username -p database_name < db/database_schema.sql
   ```
   Replace `username` with your MySQL username, `database_name` with the name of your database, and `db/database_schema.sql` with the path to the SQL file.

### Configure Currency Fetcher

Open `currency_fetcher.py` and locate the function:

```python
def fetch_and_update_currencies():
    # implement your method to fetch_and_update_currencies
    # You will need to write into currencies.json and return_currencies.json present in current directory
    # Make sure to use /helpers/currencies/file.extension to avoid errors if running from root of project. Otherwise, if you run it from its directory, just file.extension will work.
    pass
```

You need to implement the function to fetch the currency rates and update them. The rates should be in the following format:

```json
{
    "ADA": {
        "code": "ADA",
        "value": 1.6935283055,
        "name": "Cardano",
        "country": "N/A"
    },
    "AED": {
        "code": "AED",
        "value": 3.6724706177,
        "name": "UAE Dirham",
        "country": "United Arab Emirates"
    },
    ...
}
```

You can also utilize the following mappings for currency names and countries:

```python
CURRENCY_NAMES = {
    "ADA": "Cardano",
    "AED": "UAE Dirham",
    "AFN": "Afghan Afghani",
    ...
}

CURRENCY_COUNTRIES = {
    "ADA": "N/A",
    "AED": "United Arab Emirates",
    "AFN": "Afghanistan",
    ...
}
```

This will help you in naming currencies and their respective countries when fetching and updating the data.

---

## Donate or Support

If you find this project helpful and would like to support its development, consider donating through **Patreon**:

[Support on Patreon](https://www.patreon.com/techyHaroon)

---

## Running the Application

After setting everything up, run the application using the following command:

```bash
python app.py
```

---

## License

This project is licensed under the terms of the GNU General Public License version 3 (GPL-3.0).

## Credits

- **Muhammad Haroon (Techy-Haroon)**: Developer of Hero2Tech - Currency Conversion API.
- **Google OAuth2**: Authentication via Google.
- **hCaptcha**: Security for forms.
