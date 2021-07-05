// Simple email sending functions, also available as a command line.

// This provides a comprehensive method to construct MIME encoded emails
// Simply making an email with plain text body is very easy.
// Constructing multi-level MIME is also possible
// Signing and Encrypting is made easy

// How to use...
// Start by creating a new email_t using email_new(), pass a FILE* to write to body
// Write to body as you wish, default is text/plain and utf-8
// Use email_address to set From, To, etc
// Use email_send to send the email

// Signing and encryption
//
// To sign, simply include EMAIL_SIGN in flags.
// The envelope from address is last header added of type "From" or "Sender"
// This is used to find the signature unless X-Signed-By is added, in which
// case that is used (and EMAIL_SIGN is assumed). The secret key must not have a passphrase.
//
// To encrypt, simply include EMAIL_ENCRYPT in flags, the recipients are all email
// address headers added that are "To", "Cc" or "Bcc". This means Bcc may be deducible.
// For more security use add_address of type "X-Encrypt-To" with explicit keyid or fpr
// If X-Encrypt-To is used at all then only keys added as X-Encrypt-To are used, and EMAIL_ENCRYPT is assumed
//
// Normally only the body text is signed and/or encrypted. To use PGP/MIME for the email
// and hence sign and/or encrypt the whole email with attachments add EMAIL_PGPMIME flag

// Multipart MIME
// When using email_add, you add a new part and get a new email_t handle
// You can, for example, add multiple parts to the top level email_t from email_new() which are attachments
// But you can add sub parts to any parts you add if you wish
// Adding a sub part where the part already has a body will move that body to make it the first sub part then add the new one
// This makes the parent multipart/mixed
// However you can overwrite that to other types such as multipart/alternate
// You do not need to add border=, this is added to all multipart/ types automatically
// You do not need to add multipart/encrypted or multipart/signed, this is done automatically.

struct email_s;
typedef struct email_s *email_t;

// Creating a new email
// The optional argument, if passes, causes the body to be text/plain and provides a FILE* to which the body can be written
email_t email_new(FILE**);

// Setting subject
void email_subject (email_t e, const char *fmt, ...);

// Setting addresses
// This adds address, use type as "To","From","Cc","Bcc","Sender", etc
// Normally only used on the email_t returned from email_new() but can be used on any part
void email_address(email_t,const char *type,const char *email, const char *name);

// Arbitrary headers
// This allows arbitrary additional headers to be added
// Normally only used on the email_t returned from email_new() but can be used on any part
void email_header(email_t,const char*type,const char *fmt,...);

// Add additional parts to email
// You can add to top level email or to any previously added part to add sub objects
// If the part you are adding to has no body, this becomes the body for that part not a new part
// If the part you are adding to has a body already this is moved to be the first sub part to make it multipart/mixed
// The mime type of the new part is set based on file extension and mime.types but can be changed if need
// sourcefile is optional, if specified the body of the new part is set to content of file
// FILE** is optional, if specified the body is created and you can write to the FILE*
// (use sourcefile or FILE** not both)
// filename is optional, mime type set from ext of source file if no filename, default application/octet-stream
email_t email_add(email_t,const char *filename,const char *sourcefile,FILE **);

// Set a mime type of a part, overriding whatever is already set
void email_type(email_t,const char *mimetype);

// Special case for HTML in emails
// This scans the attachment specified, which should be text/html for data: URIs
// It replaces them with cid: URIs, makes the attachment multipart/related and
// adds the image files as the related objects. The domain is used in the cid
void email_cid(email_t,const char *domain);

// Sending email - returns NULL if OK, else returns error text
// signer is optional, if not present then from address is used to sign
// flags (see below)
// Once used all email_t handles are freed and no longer valid
const char *email_send(email_t,int flags);
const char *email_send_save(email_t,int flags,const char *savefilename);

// Other general stuff
email_t email_first(email_t e); // return first sub item in email
email_t email_alternative(email_t e);   // Make an email a sub email in multipart/alternative

#define	EMAIL_SIGN	1	// Sign
#define	EMAIL_ENCRYPT	2	// Encrypt
#define	EMAIL_PGPMIME	4	// Use PGP/MIME (signs and/or encrypts any attachments as well)
#define	EMAIL_NOPIN	8	// There is no PIN
#define	EMAIL_DONTSEND	64	// Don't actually send
#define	EMAIL_DEBUG	128	// Write out to stdout and extra errors to stderr

#ifdef	GPGME_H
// Special case where GPG context already exists rather than using default GPG keyring
void email_gpgctx(email_t e,gpgme_ctx_t ctx);       // Set GPG context to use - include gpgme.h first if using this
#endif
