CREATE TABLE "public"."user"
(
  "id" uuid NOT NULL,
  "email" varchar(255),
  "hashedPassword" varchar(255),
  "authType" varchar(255),
  "createdAt" timestamptz,
  "updatedAt" timestamptz,
  "isVerified" bool DEFAULT false,
  "hashedRT" varchar(255),
  PRIMARY KEY("id")
);


CREATE TABLE "public"."profile"
(
    "id" uuid NOT NULL,
    "name" varchar(255),
    "imageUrl" varchar(255),
    "metadata" json,
    "userId" uuid,
    "createdAt" timestamptz NOT NULL,
    "updatedAt" timestamptz NOT NULL,
    CONSTRAINT "profile_id_fkey" FOREIGN KEY ("id") REFERENCES "public"."user"("id") ON UPDATE CASCADE ON DELETE CASCADE,
    PRIMARY KEY ("id")
);
