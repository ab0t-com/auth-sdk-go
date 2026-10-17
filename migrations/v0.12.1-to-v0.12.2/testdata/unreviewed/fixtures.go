package fixtures

// A hand-built JWT-shaped fixture with padding: v0.12.2 refuses it (R1). (Short on purpose: not a real JWT.)
const paddedFixture = "eyJhbGci.eyJzdWIi.c2ln="

// A canonical one is fine.
const canonicalFixture = "eyJhbGci.eyJzdWIi.c2ln"
