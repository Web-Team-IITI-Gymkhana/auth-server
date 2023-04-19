CREATE TABLE "public"."user"
(
  "id" uuid NOT NULL,
  "email" varchar
(255),
  "hashedPassword" varchar
(255),
  "authType" varchar
(255),
  "createdAt" timestamptz,
  "updatedAt" timestamptz,
  "isVerified" bool DEFAULT false,
  "hashedRT" varchar
(255),
  PRIMARY KEY
("id")
);


CREATE TABLE "public"."profile"
(
  "id" uuid NOT NULL,
  "Name" varchar(255),
  "imageUrl" varchar(255),
  "Metadata" json,
  "profileId" uuid,
  "createdAt" timestamptz NOT NULL,
  "updatedAt" timestamptz NOT NULL,
  "UserId" uuid,
  CONSTRAINT "profile_UserId_fkey" FOREIGN KEY
("UserId") REFERENCES "public"."user"
("UserId") ON
DELETE
SET NULL
ON
UPDATE CASCADE,
  PRIMARY KEY ("id")
);

