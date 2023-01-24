// Simple email functions

#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <err.h>
#include <stdarg.h>
#include <execinfo.h>
#include <locale.h>
#ifndef	LIGHT
#include <gpgme.h>
#endif
#include <dirent.h>
#include "libemail.h"

#define	CRLF	"\r\n"          // Standard for SMTP
#define	STRIPCR                 // For exim

static const char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct address_s address_t;     // Used for lists of addresses that are in headers
struct address_s {
   address_t *next;
   char *address;
};

typedef struct file_s file_t;
struct file_s {
   size_t len;
   char *data;
   FILE *file;
   int isinline:1;              // Inline rather than attachment
   int text:1;                  // If text encoded (i.e. 7bit)
   char *filename;              // Filename
};

struct email_s {
   email_t next;                // Next in parent
   file_t *body;                // Body data
   file_t *head;                // Head data
   char *mimetype;              // Mime type of this entry
#ifndef	LIGHT
   gpgme_ctx_t gpgctx;          // Existing GPGME context
#endif
   char *from;                  // From/Sender
   char *signer;                // Signer address
   address_t *addresses;        // Recipient addresses
   email_t sub;                 // First sub entry
   email_t sublast;             // Last sub entry
   unsigned long long part;     // Multipart separator
   int encryptto:1;             // Explicit list of encrypt to key ids in addresses
};

static address_t *freeaddresses(address_t * a)
{
   while (a)
   {
      address_t *n = a->next;
      free(a->address);
      free(a);
      a = n;
   }
   return NULL;
}

static void freeemail(email_t e)
{
   email_t a = e->sub;
   while (a)
   {
      email_t n = a->next;
      freeemail(a);
      a = n;
   }
   if (e->from)
      free(e->from);
   if (e->signer)
      free(e->signer);
   if (e->mimetype)
      free(e->mimetype);
   if (e->body)
   {
      if (e->body->filename)
         free(e->body->filename);
      free(e->body);
   }
   if (e->head)
      free(e->head);
   e->addresses = freeaddresses(e->addresses);
   free(e);
}

static char *mimetype(const char *filename)
{                               // Find mime type, and return malloced
   const char *type = NULL;
   if (filename)
   {
      char line[1000];
      const char *ext = strrchr(filename, '.');
      if (ext)
      {
         ext++;
         int extlen = strlen(ext);
         FILE *m = fopen("/etc/mime.types", "r");
         if (m)
         {
            while (!type && fgets(line, sizeof(line), m))
            {
               char *p;
               for (p = line; *p && !isspace(*p); p++);
               while (*p && !type)
               {
                  while (isspace(*p))
                     *p++ = 0;
                  char *q = p;
                  while (*p && !isspace(*p))
                     p++;
                  if (p - q == extlen && !strncasecmp(q, ext, extlen))
                  {
                     type = line;
                     break;
                  }
               }
            }
            fclose(m);
         }
      }
   }
   return strdup(type ? : "application/octet-stream");
}

static void rfc5335(FILE * o, const char *value, int quote)
{                               // Encoding for non ASCII names, subjects, etc
   if (!value)
      return;
   const char *p;
   if (quote)
      fputc('"', o);
   for (p = value; *p >= ' ' && *p < 127 && (!quote || *p != '"'); p++);
   if (*p)
   {
      fprintf(o, "=?utf8?Q?");
      for (p = value; *p; p++)
         if (*p >= ' ' && *p < 127 && *p != '=' && *p != '?' && *p != '_' && (!quote || *p != '"'))
            fputc(*p, o);
         else
            fprintf(o, "=%02X", (unsigned char) *p);
      fprintf(o, "?=");
   } else
      fprintf(o, "%s", value);  // simple US ascii
   if (quote)
      fputc('"', o);
}


// Piped stuff
static int pipeclose(FILE * o, pid_t child)
{
   if (fileno(o) != 2)
      fclose(o);
   if (child)
   {
      int status = -1;
      waitpid(child, &status, 0);
      return status;
   }
   return 0;
}

static FILE *pipeemail(pid_t * childp, const char *from)
{                               // Create a pipe to a sendmail command
   int i[2];
   if (pipe(i))
      err(1, "pipe failed");
   pid_t child = fork();
   if (child < 0)
      err(1, "Fork failed");
   if (child)
   {                            // parent
      if (childp)
         *childp = child;
      close(i[0]);
      FILE *f = fdopen(i[1], "w");
      if (!f)
         err(1, "fdopen failed");
      return f;
   }
   // child
   close(i[1]);
   if (!dup2(i[0], 0))
      close(i[0]);
   execl("/usr/sbin/sendmail", "sendmail", "-B8BITMIME", "-t", from ? "-f" : NULL, from, NULL);
   err(1, "Exec failed");
   return NULL;
}

email_t email_new(FILE ** op)
{                               // Create new email object
   email_t e = malloc(sizeof(*e));
   if (!e)
      return NULL;              // Failed
   memset(e, 0, sizeof(*e));
   if (op)
   {                            // Standard text/plain body
      e->body = malloc(sizeof(*e->body));
      memset(e->body, 0, sizeof(*e->body));
      *op = e->body->file = open_memstream(&e->body->data, &e->body->len);
      e->mimetype = strdup("text/plain; charset=utf-8");
      e->body->isinline = 1;
   }
   email_header(e, "MIME-Version", "1.0");
   return e;
}

#ifndef	LIGHT
void email_gpgctx(email_t e, gpgme_ctx_t ctx)
{                               // Set GPG context to use
   e->gpgctx = ctx;
}
#endif

void email_type(email_t e, const char *mimetype)
{
   if (e->mimetype)
   {
      free(e->mimetype);
      e->mimetype = NULL;
   }
   if (mimetype)
      e->mimetype = strdup(mimetype);
}

void email_cid(email_t e, const char *domain)
{                               // Replace data: URIs with cid: URIs and related attachments
   if (!e || !e->body || !e->mimetype || strcasecmp(e->mimetype, "text/html"))
      return;                   // Not valid
   // New body...
   if (e->body->file)
   {                            // Close to make it complete
      fclose(e->body->file);
      e->body->file = NULL;
   }
   char *p = e->body->data;
   if (!p || !*p)
      return;                   // Nothing there
   // New content
   int count = 0;
   file_t *newbody = malloc(sizeof(*newbody));
   if (!newbody)
      errx(1, "malloc");
   memset(newbody, 0, sizeof(*newbody));
   FILE *o = open_memstream(&newbody->data, &newbody->len);
   if (!o)
      errx(1, "malloc");
   while (*p)
   {
      if (!isalnum(*p) && !strncmp(p + 1, "data:image/", 11))
      {                         // Looks like a data URI
         char *q = p + 12;
         while (isalpha(*q))
            q++;
         if (!strncmp(q, ";base64,", 8))
         {                      // yep, really looks like an image...
            // base 64 decode
            FILE *i = NULL;
            email_t a = email_add(e, NULL, NULL, &i);
            a->body->isinline = 1;
            // Decode base64
            char *z = q + 8;
            int b = 0,
                v = 0;
            while (*z)
            {
               char *q = strchr(BASE64, *z);
               if (!q)
               {                // Bad character
                  if (isspace(*z) || *z == '\r' || *z == '\n')
                  {             // Allowed whitespace
                     z++;
                     continue;
                  }
                  break;        // Finished
               }
               v = (v << 6) + (q - BASE64);
               b += 6;
               z++;
               if (b >= 8)
               {                // output byte
                  b -= 8;
                  fputc(v >> b, i);
               }
            }
            while (*z == '=')
               z++;
            if (a->mimetype)
               free(a->mimetype);
            if (asprintf(&a->mimetype, "%.*s", (int) (q - p - 6), p + 6) < 0)
               errx(1, "malloc");
            if (!a->part)
            {
               FILE *f = fopen("/dev/urandom", "r");
               if (fread(&a->part, sizeof(a->part), 1, f) != 1)
                  err(1, "random");
               fclose(f);
            }
            email_header(a, "Content-ID", "<%llu@%s>", a->part, domain);
            fputc(*p++, o);
            fprintf(o, "cid:%llu@%s", a->part, domain);
            p = z;
            count++;
            continue;
         }
      }
      // Copy
      fputc(*p++, o);
   }
   if (!count)
   {                            // No changes, leave as it is.
      if (newbody->data)
         free(newbody->data);
      free(newbody);
      return;
   }
   // Replace
   if (e->mimetype)
      free(e->mimetype);
   e->mimetype = strdup("multipart/related; type=\"text/html\"");
   e = e->sub;                  // The body will have moved
   if (!e)
      errx(1, "WTF");
   newbody->text = e->body->text;
   newbody->isinline = e->body->isinline;
   newbody->filename = e->body->filename;
   if (e->body)
   {
      if (e->body->data)
         free(e->body->data);
      free(e->body);
   }
   e->body = newbody;
   e->body->file = o;
}

const char *email_send_save(email_t e, int flags, const char *copy)
{                               // Sending email (copy to a file)
   if (e->encryptto)
      flags |= EMAIL_ENCRYPT;
   if (e->signer)
      flags |= EMAIL_SIGN;
   // Close all file handles
   void emailclose(email_t e) {
      if (e->body && e->body->file)
      {
         fclose(e->body->file);
         e->body->file = NULL;
      }
      if (e->head && e->head->file)
      {
         fclose(e->head->file);
         e->head->file = NULL;
      }
      email_t s;
      for (s = e->sub; s; s = s->next)
         emailclose(s);
   }
   emailclose(e);
   // Actually sending MIME
   void sendmime(email_t e, FILE * o) {
      if (e->head)
         fwrite(e->head->data, e->head->len, 1, o);
      // Check if can be sent without encoding
      unsigned char *p = NULL,
          *z = NULL,
          utf8 = 0;
      if (e->body)
      {
         unsigned char *sol = (unsigned char *) e->body->data;
         z = (unsigned char *) e->body->data + e->body->len;
         for (p = (unsigned char *) e->body->data; p < z && p < sol + 200 && *p; p++)
            if (*p == '\r' || *p == '\n')
               sol = p + 1;
            else if (*p < ' ' && *p != '\t')
               break;           // Only allow some control characters to be on safe side
            else if (*p > 0xF0)
            {                   // UTF8
               utf8 = 1;
               if (p + 3 >= z || p[1] < 0x80 || p[1] >= 0xC0 || p[2] < 0x80 || p[2] >= 0xC0 || p[3] < 0x80 || p[3] >= 0xC0)
                  break;
               p += 3;
            } else if (*p > 0xE0)
            {                   // UTF8
               utf8 = 1;
               if (p + 2 >= z || p[1] < 0x80 || p[1] >= 0xC0 || p[2] < 0x80 || p[2] >= 0xC0)
                  break;
               p += 2;
            } else if (*p > 0xC0)
            {                   // UTF8
               utf8 = 1;
               if (p + 1 >= z || p[1] < 0x80 || p[1] >= 0xC0)
                  break;
               p += 1;
            } else if (*p >= 0x80)
               break;           // Some other combination not valid UTF-8
      }
      if (e->mimetype)
      {
         if (!e->part)
         {
            FILE *f = fopen("/dev/urandom", "r");
            if (fread(&e->part, sizeof(e->part), 1, f) != 1)
               err(1, "random");
            fclose(f);
         }
         fprintf(o, "Content-Type: %s", e->mimetype);
         if (p == z && utf8 && !strncasecmp(e->mimetype, "text/", 5))
            fprintf(o, "; charset=UTF-8");
         if (e->sub)
            fprintf(o, "; boundary=CUT-HERE-%llu", e->part);
         fprintf(o, CRLF);
      }
      if (p == z && e->mimetype && ((e->body && e->body->text) || (!strncasecmp(e->mimetype, "text/", 5) && !(flags & EMAIL_PGPMIME)) || !strncasecmp(e->mimetype, "message/", 8) || !strncasecmp(e->mimetype, "application/pgp", 15) || !strncasecmp(e->mimetype, "multipart/encrypted", 19)))
      {
         if (e->body && (e->body->isinline || e->body->filename))
         {
            fprintf(o, "Content-Disposition: %s", e->body->isinline ? "inline" : "attachment");
            if (e->body->filename)
               fprintf(o, ";filename=\"%s\"", e->body->filename);
            fprintf(o, CRLF);
         }
         if (p < z)
            fprintf(o, "Content-Transfer-Encoding: binary" CRLF);
         fprintf(o, CRLF);
         if (e->body && e->body->data)
            fwrite(e->body->data, e->body->len, 1, o);
      } else if (e->body && e->body->data)
      {
         fprintf(o, "Content-Disposition: %s", e->body->isinline ? "inline" : "attachment");
         if (e->body->filename)
            fprintf(o, ";filename=\"%s\"", e->body->filename);
         fprintf(o, CRLF);
         fprintf(o, "Content-Transfer-Encoding: base64" CRLF);
         fprintf(o, CRLF);
         size_t i = 0,
             b = 0,
             v = 0,
             c = 0;
         while (i < e->body->len)
         {
            b += 8;
            v = (v << 8) + e->body->data[i++];
            while (b >= 6)
            {
               b -= 6;
               fputc(BASE64[(v >> b) & ((1 << 6) - 1)], o);;
               if (++c == 76)
               {
                  fprintf(o, CRLF);
                  c = 0;
               }
            }
         }
         if (b)
         {                      // final bits
            b += 8;
            v <<= 8;
            b -= 6;
            fputc(BASE64[(v >> b) & ((1 << 6) - 1)], o);
            while (b)
            {                   // padding
               while (b >= 6)
               {
                  b -= 6;
                  fputc('=', o);
               }
               if (b)
                  b += 8;
            }
         }
         if (c)
            fprintf(o, CRLF);
      }
      if (e->sub)
      {
         email_t s;
         for (s = e->sub; s; s = s->next)
         {
            fprintf(o, CRLF "--CUT-HERE-%llu" CRLF, e->part);
            sendmime(s, o);
         }
         fprintf(o, CRLF "--CUT-HERE-%llu--" CRLF, e->part);
      }
   }
   const char *err = NULL;
#ifndef LIGHT
   gpgme_error_t gpgerr;
   gpgme_ctx_t ctx = NULL;
   if (flags & (EMAIL_ENCRYPT | EMAIL_SIGN))
   {                            // Sort ctx for GPGME
      if (e->gpgctx)
         ctx = e->gpgctx;
      else
      {
         setlocale(LC_ALL, "");
         gpgme_check_version(NULL);
         if ((gpgerr = gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL))))
            err = gpgme_strerror(gpgerr);
#ifdef LC_MESSAGES
         if ((gpgerr = gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL))))
            err = gpgme_strerror(gpgerr);
#endif
         if ((gpgerr = gpgme_new(&ctx)))
            err = gpgme_strerror(gpgerr);
      }
      gpgme_set_armor(ctx, 1);
      if (flags & EMAIL_NOPIN)
      {
         gpgme_error_t cb(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {    // No PIN
            char nl = '\n';
            if (write(fd, &nl, 1) != 1)
               return -1;
            return 0;
         }
         gpgme_set_passphrase_cb(ctx, &cb, NULL);
      }
   }
   gpgme_key_t *keys = NULL;    // keys for encryption
   int keyn = 0;
   if (flags & EMAIL_ENCRYPT)
   {                            // Sort list of targets for encryption
      address_t *r;
      for (r = e->addresses; r; r = r->next)
      {
         if ((gpgerr = gpgme_op_keylist_start(ctx, r->address, 0)))
            err = gpgme_strerror(gpgerr);
         int count = 0;
         gpgme_key_t key = NULL;
         while (!(gpgerr = gpgme_op_keylist_next(ctx, &key)))
         {
            if (flags & EMAIL_DEBUG)
            {
               fprintf(stderr, "Consider key %s %s\n", key->subkeys->keyid, key->subkeys->fpr);
               fprintf(stderr, "Encrypt: %s\n", key->can_encrypt ? "Yes" : "No");
               fprintf(stderr, "Invalid: %s\n", key->invalid ? "Yes" : "No");
               fprintf(stderr, "Expired: %s\n", key->expired ? "Yes" : "No");
               fprintf(stderr, "Revoked: %s\n", key->revoked ? "Yes" : "No");
               fprintf(stderr, "Disabled: %s\n", key->disabled ? "Yes" : "No");
               fprintf(stderr, "Trust: %d\n", key->owner_trust);
            }
            if (key->can_encrypt && !key->invalid && !key->expired && !key->revoked && !key->disabled && ((key->owner_trust >= GPGME_VALIDITY_MARGINAL && !e->encryptto) || (e->encryptto && (!strcmp(key->subkeys->keyid, r->address) || !strcmp(key->subkeys->fpr, r->address)))))
            {                   // Key looks OK, check UIDs
               gpgme_user_id_t u = NULL;
               if (!e->encryptto)
                  for (u = key->uids; u; u = u->next)
                     if (u->email && !strcmp(u->email, r->address) && !u->revoked && !u->invalid && u->validity >= GPGME_VALIDITY_MARGINAL)
                        break;  // Found a good UID matching email, so usable
               if (e->encryptto || u)
               {
                  keys = realloc(keys, (keyn + 2) * sizeof(*keys));
                  keys[keyn++] = key;
                  keys[keyn] = NULL;
                  count++;
               }
            }
         }
         if (gpgme_err_code(gpgerr) == GPG_ERR_EOF)
         {
            if (!count)
            {
               err = "Encryption key not found";
               if (flags & EMAIL_DEBUG)
                  fprintf(stderr, "Cannot find encryption key for %s\n", r->address);
            }
         } else if (gpgerr)
            err = gpgme_strerror(gpgerr);
         if ((gpgerr = gpgme_op_keylist_end(ctx)))
            err = gpgme_strerror(gpgerr);
         if (key)
         {
            keys = realloc(keys, (keyn + 2) * sizeof(*keys));
            keys[keyn++] = key;
            keys[keyn] = NULL;
         }
      }
   }
   gpgme_key_t sign = NULL;
   if (flags & EMAIL_SIGN)
   {
      if ((gpgerr = gpgme_op_keylist_start(ctx, e->signer ? : e->from, 1)))
      {
         err = gpgme_strerror(gpgerr);
         if (flags & EMAIL_DEBUG)
            fprintf(stderr, "gpgme_op_keylist_start: %s\n", err);
      }
      gpgme_key_t key = NULL;
      while (!(gpgerr = gpgme_op_keylist_next(ctx, &key)))
      {
         if (flags & EMAIL_DEBUG)
            fprintf(stderr, "Check sign %s (%d)\n", key->uids->uid, key->revoked);
         if (!sign && key && !key->revoked && !key->expired && !key->disabled && !key->invalid && key->can_sign && key->secret)
         {
            sign = key;
            continue;
         }
         gpgme_key_unref(key);
      }
      if ((gpgerr = gpgme_op_keylist_end(ctx)))
      {
         err = gpgme_strerror(gpgerr);
         if (flags & EMAIL_DEBUG)
            fprintf(stderr, "gpgme_op_keylist_start: %s\n", err);
      }
      if (!sign)
      {
         if (!err)
            err = "No signing key";
         if (flags & EMAIL_DEBUG)
            fprintf(stderr, "No signer key %s\n", e->signer ? : e->from);
      } else
      {
         gpgme_signers_clear(ctx);
         if ((gpgerr = gpgme_signers_add(ctx, sign)))
            err = gpgme_strerror(gpgerr);
         if (!err && (flags & EMAIL_DEBUG))
            fprintf(stderr, "Sign as %s\n", sign->uids->uid);
      }
   }
   // Do sign / encrypt
   if (!err && (flags & (EMAIL_ENCRYPT | EMAIL_SIGN)))
   {
      if (flags & EMAIL_PGPMIME)
      {                         // S/MIME
         email_t n = malloc(sizeof(*n));        // New top level
         memset(n, 0, sizeof(*n));
         // Need headers and from... addresses and signers already extracted
         n->head = e->head;
         e->head = NULL;
         n->from = e->from;
         e->from = NULL;
         if (flags & EMAIL_ENCRYPT)
         {                      // Encrypt or encrypt+sign
            // Two parts
            email_t p1 = malloc(sizeof(*p1));   // New part 1
            memset(p1, 0, sizeof(*p1));
            email_t p2 = malloc(sizeof(*p2));   // New part 2
            memset(p2, 0, sizeof(*p2));
            n->mimetype = strdup("multipart/encrypted; protocol=\"application/pgp-encrypted\"");
            p1->mimetype = strdup("application/pgp-encrypted");
            p1->body = malloc(sizeof(*p1->body));
            memset(p1->body, 0, sizeof(*p1->body));
            p1->body->len = strlen(p1->body->data = strdup("Version: 1" CRLF));
            p2->mimetype = strdup("application/octet-stream");
            size_t len = 0;
            char *buf = NULL;
            FILE *o = open_memstream(&buf, &len);
            sendmime(e, o);
            fclose(o);
            gpgme_data_t enc = NULL;
            if ((gpgerr = gpgme_data_new_from_mem(&enc, buf, len, 0)))
               err = gpgme_strerror(gpgerr);
            gpgme_data_t res = NULL;
            if ((gpgerr = gpgme_data_new(&res)))
               err = gpgme_strerror(gpgerr);
            if (flags & EMAIL_SIGN)
            {                   // Sign and encrypt
               if ((gpgerr = gpgme_op_encrypt_sign(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, enc, res)))
                  err = gpgme_strerror(gpgerr);
            } else
            {                   // Encrypt only
               if ((gpgerr = gpgme_op_encrypt(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, enc, res)))
                  err = gpgme_strerror(gpgerr);
            }
            if (!err)
            {
               p2->body = malloc(sizeof(*p2->body));
               memset(p2->body, 0, sizeof(*p2->body));
               p2->body->data = gpgme_data_release_and_get_mem(res, &p2->body->len);
               p2->body->text = 1;
            }
            gpgme_data_release(enc);
            free(buf);
            n->sub = p1;
            p1->next = p2;
            n->sublast = p2;
            freeemail(e);
         } else
         {                      // Just sign
            // Two parts, detached signature
            email_t p2 = malloc(sizeof(*p2));   // New part 2
            memset(p2, 0, sizeof(*p2));
            n->sub = e;
            e->next = p2;
            n->sublast = p2;
            //n->mimetype = strdup ("multipart/signed; protocol=\"application/pgp-signature\"");
            p2->mimetype = strdup("application/pgp-signature");
            // Sign
            size_t len = 0;
            char *buf = NULL;
            FILE *o = open_memstream(&buf, &len);
            sendmime(e, o);
            fclose(o);
            gpgme_data_t sig = NULL;
            if ((gpgerr = gpgme_data_new_from_mem(&sig, buf, len, 0)))
               err = gpgme_strerror(gpgerr);
            gpgme_data_t res = NULL;
            if ((gpgerr = gpgme_data_new(&res)))
               err = gpgme_strerror(gpgerr);
            if ((gpgerr = gpgme_op_sign(ctx, sig, res, GPGME_SIG_MODE_DETACH)))
               err = gpgme_strerror(gpgerr);
            gpgme_sign_result_t signres = gpgme_op_sign_result(ctx);
            if (asprintf(&n->mimetype, "multipart/signed; protocol=\"application/pgp-signature\"; micalg=\"pgp-%s\"", gpgme_hash_algo_name(signres->signatures->hash_algo)) < 0)
               errx(1, "malloc");
            p2->body = malloc(sizeof(*p2->body));
            memset(p2->body, 0, sizeof(*p2->body));
            p2->body->filename = strdup("signature.pgp");
            if (!err)
               p2->body->data = gpgme_data_release_and_get_mem(res, &p2->body->len);
            gpgme_data_release(sig);
            free(buf);
         }
         e = n;
      } else
      {                         // In-line body sign/encrypt
         email_t a = e;
         if (!a->body && a->sub && a->sub->body)
            a = a->sub;
         if (!a->body || !a->body->data)
            return "Cannot find body";
         a->body->file = NULL;
         gpgme_data_t body = NULL;
         if ((gpgerr = gpgme_data_new_from_mem(&body, a->body->data, a->body->len, 0)))
            err = gpgme_strerror(gpgerr);
         gpgme_data_t res = NULL;
         if ((gpgerr = gpgme_data_new(&res)))
            err = gpgme_strerror(gpgerr);
         if ((flags & (EMAIL_ENCRYPT | EMAIL_SIGN)) == (EMAIL_ENCRYPT | EMAIL_SIGN))
         {                      // Encrypt and sign main body
            if ((gpgerr = gpgme_op_encrypt_sign(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, body, res)))
               err = gpgme_strerror(gpgerr);
            a->body->text = 1;
         } else if (flags & EMAIL_ENCRYPT)
         {                      // Encrypt main body
            if ((gpgerr = gpgme_op_encrypt(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, body, res)))
               err = gpgme_strerror(gpgerr);
            a->body->text = 1;
         } else if (flags & EMAIL_SIGN)
         {                      // Sign main body
            if ((gpgerr = gpgme_op_sign(ctx, body, res, GPGME_SIG_MODE_CLEAR)))
               err = gpgme_strerror(gpgerr);
         }
         free(a->body->data);
         a->body->data = gpgme_data_release_and_get_mem(res, &a->body->len);
         gpgme_data_release(body);
      }
   }
#endif
   if (!err)
   {                            // Sending the email
      pid_t child = 0;
#ifdef  STRIPCR
      // Special case, exim wants LF not CRLF so replace. We generate using CRLF as needed for S/MIME, etc
      size_t len = 0;
      char *buf = NULL;
      FILE *o = open_memstream(&buf, &len);
      sendmime(e, o);
      fclose(o);
      {                         // Remove CRs
         char *i = buf,
             *o = buf;
         while (*i)
         {
            if (*i != '\r')
               *o++ = *i;
            i++;
         }
         len = (o - buf);
      }
      o = stdout;
      if (!(flags & (EMAIL_DEBUG | EMAIL_DONTSEND)))
         o = pipeemail(&child, e->from ? : "");
      if ((flags & (EMAIL_DEBUG | EMAIL_DONTSEND)) != EMAIL_DONTSEND)
         if (fwrite(buf, len, 1, o) != 1)
            errx(1, "Not sent to sendmail cleanly");
      free(buf);
#else
      FILE *o = stdout;
      if (!(flags & (EMAIL_DEBUG | EMAIL_DONTSEND)))
         o = pipeemail(&child, e->from ? : "");
      if ((flags & (EMAIL_DEBUG | EMAIL_DONTSEND)) != EMAIL_DONTSEND)
         sendmime(e, o);
#endif
      if (o != stdout)
      {
         int code = pipeclose(o, child);
         if (!WIFEXITED(code))
            err = "Mail sending failed";
         else if (WEXITSTATUS(code))
            err = "Mail sending reported failure";
      }
      if (!err && copy)
      {
         o = fopen(copy, "w");
         if (!o)
            errx(1, "Cannot open %s", copy);
         sendmime(e, o);
         fclose(o);
      }
   }
   // Cleanup
#ifndef	LIGHT
   int n;
   if (sign)
      gpgme_key_unref(sign);
   for (n = 0; n > keyn; n++)
      gpgme_key_unref(keys[n]);
   if (ctx && ctx != e->gpgctx)
      gpgme_release(ctx);
#endif
   freeemail(e);
   return err;
}

const char *email_send(email_t e, int flags)
{
   return email_send_save(e, flags, NULL);
}

static void head(email_t e)
{                               // Create headers
   if (!e->head)
   {
      e->head = malloc(sizeof(*e->head));
      if (!e->head)
         errx(1, "malloc");
      memset(e->head, 0, sizeof(*e->head));
   }
   if (!e->head->file)
      e->head->file = open_memstream(&e->head->data, &e->head->len);
}

void email_address(email_t e, const char *type, const char *email, const char *name)
{
   if (!e || !type || !email)
      return;
   head(e);
   fprintf(e->head->file, "%s: ", type);
   if (name)
   {
      rfc5335(e->head->file, name, 1);
      fputc(' ', e->head->file);
   }
   fprintf(e->head->file, "<%s>" CRLF, email);
   if (!strcasecmp(type, "From") || !strcasecmp(type, "Sender"))
   {                            // From
      if (e->from)
         free(e->from);
      e->from = strdup(email);
   }
   if (!strcasecmp(type, "X-Signed-By"))
   {                            // Signer
      if (e->signer)
         free(e->signer);
      e->signer = strdup(email);
   }
   if (!strcasecmp(type, "To") || !strcasecmp(type, "Cc") || !strcasecmp(type, "Bcc") || !strcasecmp(type, "X-Encrypt-To"))
   {                            // Recipient
      if (!strcasecmp(type, "X-Encrypt-To"))
      {                         // Start making explicit  list of encrypt-to addresses
         if (!e->encryptto)
            e->addresses = freeaddresses(e->addresses);
         e->encryptto = 1;
      } else if (e->encryptto)
         return;                // We are only making explicit encrypt-to address list
      address_t *r = malloc(sizeof(*r));
      if (!r)
         errx(1, "Malloc");
      memset(r, 0, sizeof(*r));
      r->address = strdup(email);
      r->next = e->addresses;
      e->addresses = r;
   }
}

void email_subject(email_t e, const char *fmt, ...)
{                               // Set Subject
   char *subject = NULL;
   va_list ap;
   va_start(ap, fmt);
   if (vasprintf(&subject, fmt, ap) < 0)
      err(1, "malloc");
   va_end(ap);
   head(e);
   fprintf(e->head->file, "Subject: ");
   if (subject)
   {
      rfc5335(e->head->file, subject, 0);
      free(subject);
   }
   fprintf(e->head->file, CRLF);
}

email_t email_add(email_t e, const char *filename, const char *sourcefile, FILE ** op)
{                               // Add new part
   email_t a = NULL;
   if (e->body || e->sub || e->mimetype)
   {                            // Normal attachment
      a = malloc(sizeof(*a));
      if (!a)
         return NULL;
      memset(a, 0, sizeof(*a));
   } else
      a = e;                    // This is the body
   if (a->mimetype)
      free(a->mimetype);
   if (sourcefile || op)
      a->mimetype = mimetype(filename ? : sourcefile);
   else
      a->mimetype = strdup("multipart/mixed");
   if (sourcefile)
   {
      if (op)
         *op = NULL;
      struct stat s = { };
      if (stat(sourcefile, &s))
         return NULL;
      a->body = malloc(sizeof(*a->body));
      if (!a->body)
         return NULL;
      memset(a->body, 0, sizeof(*a->body));
      a->body->data = malloc(a->body->len = s.st_size);
      if (s.st_size)
      {
         if (!a->body->data)
            return NULL;
         FILE *i = fopen(sourcefile, "r");
         if (!i)
            return NULL;
         if (fread(a->body->data, s.st_size, 1, i) != 1)
            return NULL;
         fclose(i);
      }
   } else if (op)
   {
      a->body = malloc(sizeof(*a->body));
      if (!a->body)
         return NULL;
      memset(a->body, 0, sizeof(*a->body));
      a->body->file = open_memstream(&a->body->data, &a->body->len);
      *op = a->body->file;
   }
   if (filename && a->body)
      a->body->filename = strdup(filename);
   if (e != a && !e->sub && e->body)
   {                            // has body, move to sub
      email_t a = malloc(sizeof(*a));
      if (!a)
         return NULL;
      memset(a, 0, sizeof(*a));
      // Move to sub
#define m(x) a->x=e->x;e->x=NULL;
      m(mimetype);
      m(body);
      m(sub);
      m(sublast);
#undef m
      e->sub = e->sublast = a;
      e->mimetype = strdup("multipart/mixed");
   }
   if (a->body && (a == e || (e->sublast && e->mimetype && !strcasecmp(e->mimetype, "multipart/alternative") && e->sublast->body && e->sublast->body->isinline)))
      a->body->isinline = 1;
   if (e != a)
   {
      // Add this part
      if (e->sublast)
         e->sublast->next = a;
      else
         e->sub = a;
      e->sublast = a;
   }
   return a;
}

email_t email_first(email_t e)
{                               // First email item in email
   return e->sub;
}

email_t email_alternative(email_t e)
{                               // Make an email a sub email in multipart/alternative
   email_t a = malloc(sizeof(*a));
   if (!a)
      errx(1, "Malloc");
   memset(a, 0, sizeof(*a));
   a->mimetype = e->mimetype;
   e->mimetype = strdup("multipart/alternative");
   a->body = e->body;
   e->body = NULL;
   a->next = e->sub;
   e->sub = a;
   if (!a->next)
      e->sublast = e->sub;
   return a;
}

// General extra headers - we do MIME-Type, and so on automatically.
void email_header(email_t e, const char *header, const char *fmt, ...)
{
   char *value = NULL;
   va_list ap;
   va_start(ap, fmt);
   if (vasprintf(&value, fmt, ap) < 0)
      err(1, "malloc");
   va_end(ap);
   head(e);
   fprintf(e->head->file, "%s: %s" CRLF, header, value);
   if (value)
      free(value);
}

#ifndef	LIB
int main(int argc, const char *argv[])
{
   int c;
   const char *mailsubject = NULL;
   const char *envmailsubject = NULL;
   const char *maildnt = NULL;
   const char *sign = NULL;
   const char *cid = NULL;
   const char *body = NULL;
   const char *save = NULL;
   int debug = 0;
   int pgpmime = 0;
   int nobody = 0;
   int draft = 0;
   int encrypt = 0;

   poptContext optCon;          // context for parsing command-line options
   const struct poptOption optionsTable[] = {
      { "no-body", 0, POPT_ARG_NONE, &nobody, 0, "No body (else stdin is body)" },
      { "env-subject", 0, POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &envmailsubject, 0, "Subject", "utf8" },
      { "subject", 's', POPT_ARG_STRING, &mailsubject, 0, "Subject", "utf8" },
      { "name", 'n', POPT_ARG_STRING, NULL, 1, "Name (for next -f, -t, -c, -b)", "name" },
      { "from", 'f', POPT_ARG_STRING, NULL, 2, "From", "email@domain" },
      { "to", 't', POPT_ARG_STRING, NULL, 3, "To", "email@domain" },
      { "cc", 'c', POPT_ARG_STRING, NULL, 4, "Cc", "email@domain" },
      { "bcc", 'b', POPT_ARG_STRING, NULL, 5, "Bcc", "email@domain" },
      { "sender", 0, POPT_ARG_STRING, NULL, 6, "Sender", "email@domain" },
      { "reply-to", 0, POPT_ARG_STRING, NULL, 7, "Reply-To", "email@domain" },
      { "encrypt", 'E', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, NULL, 8, "Encrypt", "blank, or key ID/fpr" },
      { "dnt", 0, POPT_ARG_STRING, &maildnt, 0, "Disposition-Notification-To", "Email" },
      { "pgpmime", 'm', POPT_ARG_NONE, &pgpmime, 0, "PGP/MIME (sign/encrypt attachments)" },
      { "sign", 'S', POPT_ARG_STRING, &sign, 0, "Sign", "Key" },
      { "body", 'B', POPT_ARG_STRING, &body, 0, "Body type", "mimetype" },
      { "cid", 'C', POPT_ARG_STRING, &cid, 0, "data:->cid: change", "domain" },
      { "save", 'S', POPT_ARG_STRING, &save, 0, "Save copy", "filename" },
      { "alternative", 'a', POPT_ARG_STRING, NULL, 100, "Alternative to body", "filename" },
      { "header", 'h', POPT_ARG_STRING, NULL, 200, "Header", "Header:text" },
      { "draft", 0, POPT_ARG_NONE, &draft, 0, "Draft (don't send)" },
      { "debug", 'v', POPT_ARG_NONE, &debug, 0, "Debug" },
      POPT_AUTOHELP { }
   };

   optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
   poptSetOtherOptionHelp(optCon, "[attachments]");

   while ((c = poptGetNextOpt(optCon)) != -1)
      if (c < -1)
         errx(1, "%s: %s\n", poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(c));

   FILE *o = NULL;
   email_t e = NULL;

   if (body && nobody)
      errx(1, "Body or no body, make your mind up");

   e = email_new(nobody ? NULL : &o);
   if (!nobody && !e)
      errx(1, "Failed to create email");

   if (sign)
      email_address(e, "X-Signed-By", sign, NULL);
   if (envmailsubject && *envmailsubject == '$')
      envmailsubject++;
   if (envmailsubject)
      mailsubject = getenv(envmailsubject);
   if (mailsubject)
      email_subject(e, mailsubject);
   if (maildnt)
      email_header(e, "Disposition-Notification-To", "%s", maildnt);

   if (!nobody)
   {                            // Body from stdin
      char buf[1024];
      size_t l;
      while ((l = read(fileno(stdin), buf, sizeof(buf))) > 0)
         fwrite(buf, l, 1, o);
      if (body)
      {                         // Different body type
         email_type(e, body);
         if (cid)
            email_cid(e, cid);
      }
   }
   // Attachments
   const char *att;
   while ((att = poptGetArg(optCon)))
   {
      void addfile(email_t e, const char *att) {
         if (!att || !*att || *att == '.')
            return;
         const char *fn = strrchr(att, '/');
         if (fn)
            fn++;
         else
            fn = att;
         struct stat s;
         if (stat(att, &s) < 0)
            err(1, "Failed to access %s", att);
         if (S_ISDIR(s.st_mode))
         {                      // Directory
            if (att[strlen(att) - 1] != '/')
               e = email_add(e, fn, NULL, NULL);        // Add trailing / to include contents without extra layer
            if (chdir(att) < 0)
            {
               warn("Cannot open %s", att);
               return;
            }
            DIR *d = opendir(".");
            if (!d)
               err(1, "Cannot open %s", att);
            struct dirent *f;
            while ((f = readdir(d)))
               if (*f->d_name != '.')
                  addfile(e, f->d_name);
            closedir(d);
            if (chdir("..") < 0)
               err(1, "chdir ..");
            return;
         }
         email_t a = email_add(e, fn, att, NULL);
         if (!a)
            errx(1, "Cannot attach %s", att);
         if (cid)
            email_cid(a, cid);  // data: -> cid: (only works on text/html)
      }
      addfile(e, att);
   }

   // Other headers and alternatives
   email_t b = NULL;
   const char *name = NULL;
   poptResetContext(optCon);
   while ((c = poptGetNextOpt(optCon)) != -1)
      if (c > 0)
      {
         if (c == 1)
            name = poptGetOptArg(optCon);
         else if (c > 1 && c < 9)
         {
            if (c == 8)
               encrypt = 1;
            char *tag[] = { "From", "To", "Cc", "Bcc", "Sender", "Reply-To", "X-Encrypt-To" };
            const char *email = poptGetOptArg(optCon);
            if (email && *email == '$' && !strchr(email, '@'))
               email = getenv(email + 1);       // Assume you want expanding variables
            if (!email || !*email)
               continue;
            if (!strchr(email, '<'))
               email_address(e, tag[c - 2], email, name);       // Simple email address or similar (encrypt fingerprint for example)
            else
            {                   // lets parse out
               char *p = strdupa(email);
               while (*p)
               {
                  while (*p && isspace(*p))
                     p++;
                  char *q = p;
                  while (*q && *q != ',')
                  {
                     if (*q == '"')
                     {
                        q++;
                        while (*q && *q != '"')
                        {
                           if (*q == '\\' && q[1])
                              q++;
                           q++;
                        }
                        if (*q == '"')
                           q++;
                        continue;
                     }
                     if (*q == '<')
                     {
                        while (*q && *q != '>')
                           q++;
                        if (*q == '>')
                           q++;
                        continue;
                     }
                     q++;
                  }
                  if (*q == ',')
                     *q++ = 0;
                  char *name = p;
                  p = q;
                  // look for name part
                  char *eml = NULL;
                  for (q = name; *q && *q != '<'; q++);
                  if (*q)
                  {             // In angle brackets
                     eml = q + 1;
                  } else
                  {             // look for something with @ in it
                     for (q = name; *q && *q != '@'; q++);
                     if (*q)
                     {
                        while (q > name && !isspace(q[-1]))
                           q--;
                        eml = q;
                     }
                  }
                  if (!eml)
                     errx(1, "Cannot find email in [%s]", name);
                  // back from start of emaikl to end of name
                  q = eml;
                  if (q > name && q[-1] == '<')
                     *--q = 0;
                  while (q > p && isspace(q[-1]))
                     *--q = 0;
                  // Handle name in quotes
                  if (*name == '"')
                  {
                     name++;
                     q = name;
                     char *o = q;
                     while (*q && *q != '"')
                     {
                        if (*q == '\\' && q[1])
                           q++;
                        *o++ = *q++;
                     }
                     *o = 0;
                  }
                  // end of email
                  q = eml;
                  while (*q && *q != '>' && !isspace(*q))
                     q++;
                  *q = 0;
                  email_address(e, tag[c - 2], eml, *name ? name : NULL);
               }
            }
            name = NULL;
         } else if (c == 100)
         {                      // Alternative
            if (!b && !nobody)
            {                   // Find body and make as alternative (if no body, this file is first of alternatives)
               b = email_first(e) ? : e;
               email_alternative(b);
            }
            const char *att = poptGetOptArg(optCon);
            email_t a = email_add(b ? : e, NULL, att, NULL);
            if (!a)
               errx(1, "Cannot attach %s", att);
            if (cid)
               email_cid(a, cid);       // data: -> cid: (only works on text/html)
            if (!b)
            {                   // If no body, this was first of alternatives
               b = a;
               email_alternative(b);
            }
         } else if (c == 200)
         {
            const char *h = poptGetOptArg(optCon);
            if (!h)
               errx(1, "No header");
            h = strdupa(h);
            char *c = strchr(h, ':');
            if (!c)
               errx(1, "No colon in %s", h);
            *c++ = 0;
            while (*c && isspace(*c))
               c++;
            email_header(e, h, c);
         }

      }
   if (name)
      errx(1, "Trailing --name, use these before --from, --to, --cc, --bcc");
   // Send
   const char *err = email_send_save(e, (encrypt ? EMAIL_ENCRYPT : 0) | //
                                     (sign ? EMAIL_SIGN : 0) |  //
                                     (pgpmime ? EMAIL_PGPMIME : 0) |    //
                                     (draft ? EMAIL_DONTSEND : 0) |     //
                                     (debug ? EMAIL_DEBUG : 0), save);
   if (err)
      fprintf(stderr, "%s\n", err);
   poptFreeContext(optCon);
   return err ? 1 : 0;
}
#endif
