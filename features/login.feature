Feature: User Login

  Scenario: Log into the system
    Given I am on the login page
    When I login with <email> and <password>

    Examples: 
      | email | password | message                      |
      | ccstestautomation8@gmail.com    | Grip@12345  | Welcome to Volvo Cars, Akash |
