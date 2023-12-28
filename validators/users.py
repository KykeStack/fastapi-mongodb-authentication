from pydantic import ValidationError
from typing import Optional

from localData.Countries import COUNTRIES
from datetime import datetime

import phonenumbers

class UsersValidator:
    
    @classmethod
    def validate_names(cls, name: str) -> Optional[str]:
        if not name:
            raise ValidationError("A name must be provided")
        
        if len(name) > 25:
            raise ValidationError(f"Invalid Length of name {name}")
        
        return name.capitalize()

    @classmethod
    def validate_country(cls, country: str) -> Optional[str]:
        if not country:
            raise ValidationError("A country must be provided")
        
        try:
            if country in COUNTRIES:
                return COUNTRIES[COUNTRIES.index(country)]
            else:
                raise ValidationError(f"Country name: {country}, not Found")
        except Exception as e:
            raise e

    @classmethod
    def validate_birthdate(cls, date: str) -> Optional[str]:
        if not date:
            raise ValidationError("A birthdate must be provided")
        
        valid_formats: list[str] = ['%d/%m/%Y', '%d-%m-%Y', '%Y/%d/%m', '%Y-%d-%m']
        for format in valid_formats:
            try:
                parsed_date = datetime.strptime(date, format).date()
                return str(parsed_date)
            except:
                pass

        raise ValidationError(f"Invalid birthdate: {date}. List of valid formats: {valid_formats}")

    @classmethod
    def validate_phonenumber(cls, phonenumber: str) -> None:
        if not phonenumber:
            ValidationError("A valid phonenumber must be provided")
        try:
            parsed = phonenumbers.parse(phonenumber)
            if phonenumbers.is_valid_number(parsed):
                joined_phonenumber = phonenumber.replace(" ", "")
                return joined_phonenumber
            else:
                raise ValidationError(f"Invalid phone number: {phonenumber}")
        except Exception as e:
            raise ValidationError(e)

    @classmethod
    def validate_username(cls, username):
        assert username.isalnum(), 'must be alphanumeric'
        validate_username = username.capitalize()
        return validate_username
