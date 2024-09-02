package main

import (
	"context"
	"fmt"
	"log"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/db"
	"google.golang.org/api/option"
)

type Referral struct{
	ReferralID string `json:"ReferralID"`
	Username string `json:"Username"`
	TotalReferrals int `json:"TotalReferrals"`
}

func main(){
	var referalStruct Referral
	ctx := context.Background()
	conf := &firebase.Config{
        DatabaseURL: "https://kms-wealth-creations-default-rtdb.asia-southeast1.firebasedatabase.app/",
	}
	// Fetch the service account key JSON file contents
	opt := option.WithCredentialsFile("kms-wealth-creations-firebase-adminsdk-olzns-d4dcb8ed2c.json")

	// Initialize the app with a service account, granting admin privileges
	app, err := firebase.NewApp(ctx, conf, opt)
	if err != nil {
        log.Fatalln("Error initializing app:", err)
	}

	client, err := app.Database(ctx)
	if err != nil {
        log.Fatalln("Error initializing database client:", err)
	}
	log.Println("DB initialised successfully")
	referalRef := client.NewRef("/server/saving-data/fireblog/referals").Child("QWERRDRU")

        if err := referalRef.Get(ctx, &referalStruct); err != nil {
            log.Fatalln("Transaction failed to commit:", err)
        } else {
            fmt.Printf("Fetched Data: %+v\n", referalStruct) // Debugging data fetched
        }
        registerUser(ctx, client, "QWERRDRU","QWERRDR1")
}

func registerUser(ctx context.Context, client *db.Client, referal string, referralID string) {
        log.Println("Hello from registerUser")
        var referalStruct Referral
        //getting data from post request form
        // Generate the referral ID
        
        ref := client.NewRef("server/saving-data/fireblog")
        usersRef := ref.Child("referals")
        
        // Create initial referral data
        err := usersRef.Set(ctx, map[string]*Referral{
            referralID: {
                Username:      "Username",
                ReferralID:    referralID,
                TotalReferrals: 0,
            },
        })
        if err != nil {
            log.Println("Error creating referal Data: ", err)
        }

        // reference := "server/saving-data/fireblog/referals/" + referal
        // fmt.Println("Reference Path:", reference) // Debugging reference path
        referalRef := client.NewRef("/server/saving-data/fireblog/referals").Child(referal)
        fmt.Println("Referral Code Provided:", referal) // Debugging referral code

        if err := referalRef.Get(ctx, &referalStruct); err != nil {
            log.Fatalln("Transaction failed to commit:", err)
        } else {
            fmt.Printf("Fetched Data: %+v\n", referalStruct) // Debugging data fetched
        }

        // Update the referral data if exists
        refRef := ref.Child("referals").Child(referal)
        if err := refRef.Update(ctx, map[string]interface{}{
            "ReferralID":    referalStruct.ReferralID,
            "TotalReferrals": referalStruct.TotalReferrals + 1,
            "Username":      referalStruct.Username,
        }); err != nil {
            log.Fatalln("Transaction failed to commit:", err)
        }

        fmt.Println("Referral Struct:", referalStruct)
        useRef := ref.Child("users").Child(referalStruct.Username)
        if err := useRef.Update(ctx, map[string]interface{}{
            "Referrals": referalStruct.TotalReferrals + 1,
        }); err != nil {
            log.Fatalln("Transaction failed to commit:", err)
        }
    }
