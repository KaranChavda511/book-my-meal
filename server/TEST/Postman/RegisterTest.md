curl -X POST http://localhost:5000/api/auth/register
 -H "Content-Type: application/json" \
 -d '{"firstName":"John","lastName":"Doe","email":"john@example.com","password":"SuperSecret123"}'