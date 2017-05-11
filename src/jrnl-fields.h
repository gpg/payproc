/* jrnl-fields.h - Definitions of journal fields.
 * Copyright (C) 2014 g10 Code GmbH
 *
 * This file is part of Payproc.
 *
 * Payproc is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Payproc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef JRNL_FIELDS_H
#define JRNL_FIELDS_H

enum jrnl_fields
  {
    JRNL_FIELD_DATE     = 0,  /* UTC the record was created.            */
    JRNL_FIELD_TYPE     = 1,  /* Record type.                           */
    JRNL_FIELD_LIVE     = 2,  /* 1 if this is not a test account.       */
    JRNL_FIELD_CURRENCY = 3,  /* 3 letter ISO code for the currency.    */
    JRNL_FIELD_AMOUNT   = 4,  /* Amount with decimal point.             */
    JRNL_FIELD_DESC     = 5,  /* Description for this transaction.      */
    JRNL_FIELD_MAIL     = 6,  /* Email address.                         */
    JRNL_FIELD_META     = 7,  /* Structured field with additional data. */
    JRNL_FIELD_LAST4    = 8,  /* The last 4 digits of the card.         */
    JRNL_FIELD_SERVICE  = 9,  /* Payment service (0=n/a, 1=stripe.com). */
    JRNL_FIELD_ACCOUNT  = 10, /* Account number.                        */
    JRNL_FIELD_CHARGEID = 11, /* Charge id.                             */
    JRNL_FIELD_RTXID    = 12, /* Transaction id.                        */
    JRNL_FIELD_TXID     = 13, /* Reference txid.                        */
    JRNL_FIELD_EURO     = 14, /* Amount converted to Euro.              */
    JRNL_FIELD_RECUR    = 15  /* Recurrence count.                      */
  };
#define NO_OF_JRNL_FIELDS 16

#define JRNL_FIELD_NAME_DATE     "date"
#define JRNL_FIELD_NAME_TYPE     "type"
#define JRNL_FIELD_NAME_LIVE     "live"
#define JRNL_FIELD_NAME_CURRENCY "currency"
#define JRNL_FIELD_NAME_AMOUNT   "amount"
#define JRNL_FIELD_NAME_DESC     "desc"
#define JRNL_FIELD_NAME_MAIL     "mail"
#define JRNL_FIELD_NAME_META     "meta"
#define JRNL_FIELD_NAME_LAST4    "last4"
#define JRNL_FIELD_NAME_SERVICE  "service"
#define JRNL_FIELD_NAME_ACCOUNT  "account"
#define JRNL_FIELD_NAME_CHARGEID "chargeid"
#define JRNL_FIELD_NAME_TXID     "txid"
#define JRNL_FIELD_NAME_RTXID    "rtxid"
#define JRNL_FIELD_NAME_EURO     "euro"
#define JRNL_FIELD_NAME_RECUR    "recur"


#endif /*JRNL_FIELDS_H*/
