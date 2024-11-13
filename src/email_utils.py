#
#  # This file is part of Hero2Tech Project
#  # Copyright (C) 2024 Muhammad Haroon (Techy-Haroon)
#  #
#  # This program is free software: you can redistribute it and/or modify
#  # it under the terms of the GNU General Public License as published by
#  # the Free Software Foundation, either version 3 of the License, or
#  # (at your option) any later version.
#  #
#  # This program is distributed in the hope that it will be useful,
#  # but WITHOUT ANY WARRANTY; without even the implied warranty of
#  # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  # GNU General Public License for more details.
#  #
#  # You should have received a copy of the GNU General Public License
#  # along with this program. If not, see <https://www.gnu.org/licenses/>.
#  # GitHub Repository: https://github.com/Techy-Haroon/Hero2Tech-Currency-Conversion-API
#

# email_utils.py

def generate_reset_email_content(reset_url):
    # Read the HTML template
    with open("reset_password_template.html", "r", encoding="utf-8") as file:
        template = file.read()
    
    # Replace the placeholder with the actual reset URL
    email_content = template.replace("{{reset_url}}", reset_url)
    
    return email_content

def generate_email_confirmation_content(confirmation_url):
    # Read the HTML template
    with open("email_confirmation_template.html", "r", encoding="utf-8") as file:
        template = file.read()
    
    # Replace the placeholder with the actual confirmation URL
    email_content = template.replace("{{confirmation_url}}", confirmation_url)
    
    return email_content