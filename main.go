package main

import (
	//"fmt"
	//"log"
	//"net/http"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"

	// "os"
	"strings"
	// "text/template"

	// "sync"

	// "github.com/piquette/finance-go/quote"
	// "github.com/go-resty/resty/v2"

	//"firebase.google.com/go/auth"
	"example.com/KMS-trading/utils"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/db"
	"github.com/a-h/templ/examples/integration-gin/gintemplrenderer"
	"github.com/gin-gonic/gin"

	// "github.com/google/martian/v3/body"
	"golang.org/x/crypto/bcrypt"

	//"golang.org/x/net/route"
	"google.golang.org/api/option"
	//"google.golang.org/genproto/googleapis/type/phone_number"
	//"google.golang.org/genproto/googleapis/type/phone_number"
)

func main(){
	router := gin.Default()
	ctx := context.Background()
	client, err := setUpDB(ctx)
	if err!=nil{
		log.Println("Error connecting to firebase: ",err)
	}
	router.LoadHTMLGlob("client/*")
	auth := router.Group("/auth")
	auth.Use(utils.AuthMiddleWare())
	
	auth.GET("/dashboard",func(c *gin.Context){
		c.HTML(http.StatusOK,"dashboard.html","")
	})
	auth.GET("/pastPosts",func(c *gin.Context){
		c.HTML(http.StatusOK,"past-targets.html","")
	})
	auth.GET("/privacy",func(c *gin.Context){
		c.HTML(http.StatusOK,"privacy_policy.html","hello")
	})
	auth.GET("/news",func(c *gin.Context){
		c.HTML(http.StatusOK,"news.html","")
	})
	auth.GET("/posts",getPosts(ctx,client))
	auth.GET("/getNews",getNews(ctx,client))
	auth.GET("/targets",getPastPosts(ctx,client))
	auth.GET("/logout",func(c *gin.Context){
		c.Redirect(http.StatusMovedPermanently,"http://localhost:8080/login")
	})
	// auth.GET("/settings",func(c *gin.Context){
	// 	c.HTML(http.StatusOK,"settings.html","")
	// })

	admin := router.Group("/admin")
	admin.Use(utils.AdminMiddleWare())
	admin.GET("/post",func(c *gin.Context){
		c.HTML(http.StatusOK,"admin.html","sent posts")
	})
	admin.GET("/settings",func(c *gin.Context){
		c.HTML(http.StatusOK,"post-settings.html","")
	})
		admin.GET("/privacy",func(c *gin.Context){
		c.HTML(http.StatusOK,"privacy_policy.html","hello")
	})
		admin.GET("/usersToVerify",func(c *gin.Context){
		c.HTML(http.StatusOK,"verify.html","")
	})
	admin.POST("/post",postPosts(ctx,client))
	admin.POST("/news",postNews(ctx,client))
	admin.POST("/elite",postElite(ctx,client))
	admin.GET("/posts",getPostsAdmin(ctx,client))
	admin.GET("/news",getNewsAdmin(ctx,client))
	admin.GET("/verify",getUsers(ctx,client))
	admin.PUT("/verify",verify(ctx,client))
	admin.DELETE("/deletePosts",deletePosts(ctx,client))
	admin.DELETE("/deleteNews",deleteNews(ctx,client))
	

	router.GET("/signup",func(c *gin.Context){
		c.HTML(http.StatusOK,"signup.html","hello")
	})
	router.GET("/",func(c *gin.Context){
		c.HTML(http.StatusOK,"index.html",gin.H{})
	})
	router.Static("/images","./images")
	
	router.GET("/home",func(c *gin.Context){
		c.HTML(http.StatusOK,"Home.html","hello")
	})
	router.GET("/privacy",func(c *gin.Context){
		c.HTML(http.StatusOK,"privacy_policy.html","hello")
	})
	router.GET("/aboutus",func(c *gin.Context){
		c.HTML(http.StatusOK,"aboutus.html","hello")
	})
	router.GET("/contact",func(c *gin.Context){
		c.HTML(http.StatusOK,"contact.html","hello")
	})
	router.GET("/admin",func(c *gin.Context){
		c.HTML(http.StatusOK,"adminLogin.html","hello")
	})
		router.GET("/login",func(c *gin.Context){
		c.HTML(http.StatusOK,"login.html","hello")
	})

	router.GET("/tradingview",func(c *gin.Context){
		c.HTML(http.StatusOK,"tradingview-widget.html","hello")
	})

	router.GET("/register",func(c *gin.Context){
		c.HTML(http.StatusOK,"register.html","hello")
	})

	router.GET("/style",func(c *gin.Context){
		c.HTML(http.StatusOK,"style.css","hello")
	})


	
	// router.GET("/stocks",stockPriceHandler())

	router.POST("/admin",adminLogin(ctx,client))
	router.POST("/signup",registerUser(ctx,client))
	router.POST("/login",login(ctx, client))
	router.POST("/appLogin",appLogin(ctx,client))
	router.POST("/pastPosts",postPastPosts(ctx,client))
	// Run the server on port 8080
	// getPosts(ctx,client)
	router.Run(":8080")
}

func setUpDB(ctx context.Context) (*db.Client, error){
	conf := &firebase.Config{
        DatabaseURL: "https://kms-wealth-creations-default-rtdb.asia-southeast1.firebasedatabase.app/",
	}
	// Fetch the service account key JSON file contents
	opt := option.WithCredentialsFile("utils/kms-wealth-creations-firebase-adminsdk-olzns-d4dcb8ed2c.json")

	// Initialize the app with a service account, granting admin privileges
	app, err := firebase.NewApp(ctx, conf, opt)
	if err != nil {
        log.Fatalln("Error initializing app:", err)
		return nil, err
	}

	client, err := app.Database(ctx)
	if err != nil {
        log.Fatalln("Error initializing database client:", err)
		return nil,err
	}
	log.Println("DB initialised successfully")

	return client, nil
}


func registerUser(ctx context.Context, client *db.Client) gin.HandlerFunc{
	return func(c *gin.Context){
		log.Println("Hello from registerUser")
		var referalStruct Referrals
		elite:=false
		//getting data from post request form
		name:=c.PostForm("name")
		username:=c.PostForm("username")
		fmt.Println(username)
		Email:=c.PostForm("Email")
		fmt.Println(Email)
		password:=c.PostForm("password")
		phone_number:=c.PostForm("Phone Number")
		transactionID:=c.PostForm("Transaction ID")
		course:=c.PostForm("course")
		referal:=c.PostForm("Referal Code")
		

		referralID:=fmt.Sprintf("%c%c%c%c",username[0],username[1],username[2],username[3])
		referralID=strings.ToUpper(referralID)
		referralID = referralID + utils.RandString(4)
		ref := client.NewRef("server/saving-data/fireblog")
		usersRef := ref.Child("referals")
		err := usersRef.Set(ctx, map[string]*Referrals{
			referralID:{
				Username: username,
				ReferralID: referralID,
				TotalReferrals: 0,
			},
		})
		if err!=nil{
			log.Println("Error creating referal Data: ",err)
		}
		// var userReferals int
		// var referalNumber int
		// userRef:=ref.Child(fmt.Sprintf("users/%s/Referrals",username))
		reference := "server/saving-data/fireblog/referals/"+referal
		fmt.Println(reference)
		// referalRef:=client.NewRef(fmt.Sprintf("server/saving-data/fireblog/referals/%s",referal))
		referalRef:=client.NewRef(reference)
		fmt.Println(referal)
		fmt.Println(reflect.TypeOf(referal))


		if err := referalRef.Get(ctx, &referalStruct); err != nil {
			log.Fatalln("Transaction failed to commit:", err)
		}
		refRef:=ref.Child("referals").Child(referal)
		if err := refRef.Update(ctx, map[string]interface{}{
			"ReferralID":referalStruct.ReferralID,
			"TotalReferrals": referalStruct.TotalReferrals+1,
			"Username":referalStruct.Username,
		}); err != nil {
			log.Fatalln("Transaction failed to commit:", err)
		}
		fmt.Println(referalStruct)
		useRef:=ref.Child("users").Child(referalStruct.Username)
		if err := useRef.Update(ctx, map[string]interface{}{
			"Referrals": referalStruct.TotalReferrals+1,
		}); err != nil {
			log.Fatalln("Transaction failed to commit:", err)
		}

		if course =="elite"{
			elite = true
		}

		// fmt.Println(course)
		//hashing the password
		password, err = hashPassword(password)
		if err!=nil{
			log.Println("Error hashing the password: ",err)
			c.String(http.StatusInternalServerError, "Error hashing the password")
		}

		//saving the data in the firebase db
		usersRef = ref.Child("users")
		newUser:=Users{
			Name: name,
			Username: username,
			Email: Email,
			Password: password,
			PhoneNumber: phone_number,
			TransactionID: transactionID,
			Verified: false,
			Referrals:Referrals{
				ReferralID: referralID,
				TotalReferrals: 0,
			},
			Elite: elite,
	}
		err = usersRef.Update(ctx, map[string]interface{}{
        username: newUser,
		})
	if err != nil {
        log.Fatalln("Error setting value:", err)
		c.String(http.StatusInternalServerError,"Internal Server Error")
	}
	c.String(http.StatusOK,"<h1>Successfully registered!<h1>")
	}
}

func login(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var userData Users
		var username string
		var stored_password string
		username=c.PostForm("username")
		fmt.Println(username)
		password:=c.PostForm("password")
		fmt.Println(password)
		userRef := client.NewRef("server/saving-data/fireblog/users").Child(username)
		if err := userRef.Get(ctx, &userData); err != nil {
    		log.Fatalf("error getting user data: %v", err)
			c.String(http.StatusInternalServerError,"There was some error while fetching user data. Please try again")
			return
		}
		stored_password = userData.Password
		// fmt.Println(stored_password)

		err := checkPasswordHash(password,stored_password)
		if err!= nil {
			fmt.Println("Wrong password: ", err)	
			// c.String(http.StatusBadRequest, "<div id=\"notif\" class=\"notif\" hx-swap-oob=\"true\">Wrong Password!!</div>")
			c.String(http.StatusBadRequest,"Wrong Password!!")
			return
		}

		verified:=userData.Verified
		if !verified{
			c.HTML(http.StatusOK,"notverified.html","hello")
			return
		}
		
		erro:=utils.GenerateTokensAndSetCookies(userData.Username,c)
		if erro!=nil{
			log.Println("Error generating Token: ",erro)
			c.String(http.StatusInternalServerError,"Couldn't generate token. Please try again")
			return
		}

		c.Header("Hx-Redirect","/auth/dashboard")
		c.Header("Hx-Push-Url","/auth/dashboard")
		c.HTML(http.StatusBadRequest,"dashboard.html","not verified")
		
	}
}

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}

func checkPasswordHash(password, hash string) error {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err
}

func adminLogin(ctx context.Context,client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var adminData Admin
		var username string
		var stored_password string
		username=c.PostForm("username")
		fmt.Println(username)
		password:=c.PostForm("password")
		fmt.Println(password)
		userRef := client.NewRef("server/saving-data/fireblog/admins").Child(username)
		if err := userRef.Get(ctx, &adminData); err != nil {
    		log.Fatalf("error getting user data: %v", err)
			c.String(http.StatusInternalServerError,"Couldn't get user data.Please try again")
		}
		stored_password = adminData.Password
		fmt.Println(stored_password)

		err := checkPasswordHash(password,stored_password)
		if err!= nil {
			fmt.Println("Wrong password: ", err)
			c.String(http.StatusBadRequest, "Wrong Password!!")
			return
		}
		
		erro:=utils.GenerateTokensForAdmin(adminData.Username,c)
		if erro!=nil{
			log.Println("Error generating Token: ",erro)
			c.String(http.StatusInternalServerError,"Internal Server Error. Please try again")
			return
		}
		c.Header("Hx-Redirect","/admin/post")
		c.Header("Hx-Push-Url","/admin/post")
		c.HTML(http.StatusOK,"admin.html","hello")
		}
}

func postPosts(ctx context.Context, client *db.Client) gin.HandlerFunc{
    return func(c *gin.Context){
        //getting data from post request form
        stock_name:=c.PostForm("name")

        buying_price:=c.PostForm("buying_price")

        target_price:=c.PostForm("target_price")
        comments:=c.PostForm("comments")
        exchange:=c.PostForm("exchange")
		current_price:=c.PostForm("current_price")

        //saving the data in the firebase db
        ref := client.NewRef("server/saving-data/fireblog/posts")
		newPost := Posts{
            Comments:      comments,
            Buying_price: buying_price,
            Exchange:      exchange,
            Stock_name:    stock_name,
            Target_price:  target_price,
			Current_price: current_price,
        }

        // Generate a new key
        newKey := stock_name

        // Create a map to hold the new entry
        update := map[string]interface{}{
            newKey: newPost,
        }
        err := ref.Update(ctx, update)
    if err != nil {
        log.Fatalln("Error setting value:", err)
        c.String(http.StatusInternalServerError,"Internal Server Error")
    }
	// c.Header("Hx-Refresh","true")
	c.Header("Hx-Trigger-After-Swap","reset")
    c.String(http.StatusOK,"Successfully Posted!!")
    }
}

func postNews(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context)  {
		news:=c.PostForm("news")
		new:="news"

		//saving the data in the firebase db
		
		ref := client.NewRef("server/saving-data/fireblog")
		usersRef := ref.Child("news")
		err := usersRef.Set(ctx, map[string]*News{
        new: {
                New: news,
        },
		})
	if err != nil {
        log.Fatalln("Error setting value:", err)
		c.String(http.StatusInternalServerError,"Internal Server Error")
	}
	c.String(http.StatusOK,"Successfully Posted!!")
	}
}

func getPosts(ctx context.Context, client *db.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var posts map[string]Posts
		var elitePosts map[string]Posts
		// username
		userRef := client.NewRef("server/saving-data/fireblog/posts")
		if err := userRef.Get(ctx, &posts); err != nil {
			log.Printf("error getting user data: %v", err)
			c.String(http.StatusInternalServerError, "Error fetching posts")
			return
		}

		eliteRef := client.NewRef("sever/saving-data/fireblog/elite-posts")
		if err := eliteRef.Get(ctx, &elitePosts);err!=nil{
			log.Println("error getting elite data: %v",err)
			c.String(http.StatusInternalServerError,"Error fetching elite posts")
			return
		}

		// current_prices := make([]string, len(posts))
		// var wg sync.WaitGroup
		// errors := make(chan error, len(posts))

		// i := 0
		// for _, p := range posts {
		// 	wg.Add(1)
		// 	go func(i int, symbol, exchange string) {
		// 		defer wg.Done()
		// 		price, err := stockPriceHandler(symbol, exchange)
		// 		if err != nil {
		// 			errors <- err
		// 			return
		// 		}
		// 		current_prices[i] = price
		// 	}(i, p.Stock_name, p.Exchange)
		// 	i++
		// }

		// wg.Wait()
		// close(errors)

		// for err := range errors {
		// 	log.Printf("Error fetching stock price: %v", err)
		// }

		// log.Print("Current prices:", current_prices)
		r := gintemplrenderer.New(c.Request.Context(), http.StatusOK, PostsTemplate(posts))
		c.Render(http.StatusOK, r)
	}
}

func getNews(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var news map[string]News
		// Hey:="RELIANCE"
		userRef := client.NewRef("server/saving-data/fireblog/news")
		if err := userRef.Get(ctx, &news); err != nil {
    		log.Fatalf("error getting user data: %v", err)
		}
		log.Print(news)
		r := gintemplrenderer.New(c.Request.Context(), http.StatusOK,NewsTemplate(news))
		c.Render(http.StatusOK, r)
	}
}

func getPostsAdmin(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var posts map[string]Posts
		// Hey:="RELIANCE"
		userRef := client.NewRef("server/saving-data/fireblog/posts")
		if err := userRef.Get(ctx, &posts); err != nil {
    		log.Fatalf("error getting user data: %v", err)
		}
		log.Print(posts)
		r := gintemplrenderer.New(c.Request.Context(), http.StatusOK,AdminPosts(posts))
		c.Render(http.StatusOK, r)
	}
}

func getNewsAdmin(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var news map[string]News
		// Hey:="RELIANCE"
		userRef := client.NewRef("server/saving-data/fireblog/news")
		if err := userRef.Get(ctx, &news); err != nil {
    		log.Fatalf("error getting user data: %v", err)
		}
		// log.Print(news)
		r := gintemplrenderer.New(c.Request.Context(), http.StatusOK,AdminNews(news))
		c.Render(http.StatusOK, r)
	}
}

func deletePosts(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		id := c.Query("stock-name")
		fmt.Println(id)
		userRef := client.NewRef(fmt.Sprintf("server/saving-data/fireblog/posts/%s",id))
		fmt.Println(userRef)
		if err := userRef.Delete(ctx); err != nil {
			log.Fatalf("error deleting user data: %v", err)
		}
		c.String(http.StatusOK,"Deleted Successfully!!")
	}
}

func deleteNews(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		id := c.Query("news")
		userRef := client.NewRef("server/saving-data/fireblog/news").Child(id)
		if err := userRef.Delete(ctx); err != nil {
			log.Fatalf("error deleting user data: %v", err)
		}
		c.String(http.StatusOK,"Deleted Successfully!!")
	}
}

func getBSEStockPrice(symbol string)(string, error){
	alphaVantageAPIKey:="Y4BJ64SY8UK1BUWF"
	url := fmt.Sprintf("%s?function=GLOBAL_QUOTE&symbol=%s.BSE&apikey=%s", alphaVantageURL, symbol, alphaVantageAPIKey)
	log.Println(url)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var stockResp BSEStockResponse
	err = json.Unmarshal(body, &stockResp)
	if err != nil {
		return "", err
	}
	price:=stockResp.GlobalQuote.Price
	return price, nil

}

func getNSEStockPrice(symbol string) (string, error) {
    client := &http.Client{}
    req, err := http.NewRequest("GET", nseURL+symbol, nil)
    if err != nil {
        return "", err
    }
    
    // Update User-Agent to a more recent browser version
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    req.Header.Set("Accept", "application/json")
    req.Header.Set("Referer", "https://www.nseindia.com/get-quotes/equity?symbol=" + symbol)
    req.Header.Set("X-Requested-With", "XMLHttpRequest")

    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }

    // Check if the response is HTML instead of JSON
    if strings.HasPrefix(string(body), "<") {
		log.Println(body)
        return "", fmt.Errorf("received HTML response instead of JSON. Response body: %s", string(body)) // Print first 1"""" characters of the response
    }

    var stockResp NSEStockResponse
    err = json.Unmarshal(body, &stockResp)
    if err != nil {
        return "", fmt.Errorf("error unmarshalling JSON: %v. Response body: %s", err, string(body))
    }

	price:=fmt.Sprintf("%f",stockResp.PriceInfo.LastPrice)

    return price, nil
}

func stockPriceHandler(symbol string,exchange string)(string,error){
				// Replace with your Alpha Vantage API key
		// apiKey := os.Getenv("ALPHA_VANTAGE_API_KEY")
		// if apiKey == "" {
		// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "API key is missing"})
		// 	return
		// }
    // symbol := c.Query("symbol")
	// exchange := strings.ToUpper(c.Query("exchange"))

	if symbol == "" || exchange == "" {
		// c.JSON(http.StatusBadRequest, gin.H{"error": "Both symbol and exchange are required"})
		return "", fmt.Errorf("Symbol or exchange field is empty")
	}

	if exchange != "BSE" && exchange != "NSE" {
		// c.JSON(http.StatusBadRequest, gin.H{"error": "Exchange should be either BSE or NSE"})
		return "", fmt.Errorf("Exchange needs to be either BSE or NSE")
	}

	var price string
	var err error

	if exchange == "BSE" {
		price, err = getBSEStockPrice(symbol)
	} else {
		price, err = getNSEStockPrice(symbol)
	}

	if err != nil {
		log.Println(err)
		// c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error fetching stock price: %v", err)})
		return "", err
	}
	log.Println(price)
	// c.String(http.StatusOK, price)
	return price, nil
}

func postPastPosts(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		stock_name:=c.PostForm("name")

        buying_price:=c.PostForm("buying_price")

        target_price:=c.PostForm("target_price")
        target:=c.PostForm("target")
        //saving the data in the firebase db
        ref := client.NewRef("server/saving-data/fireblog/pastPosts")
		newPost := PastPosts{
            Buying_price: buying_price,
            Stock_name:    stock_name,
            Target_price:  target_price,
			Target: target,
        }

        // Generate a new key
        newKey := stock_name

        // Create a map to hold the new entry
        update := map[string]interface{}{
            newKey: newPost,
        }
        err := ref.Update(ctx, update)
    if err != nil {
        log.Fatalln("Error setting value:", err)
        c.String(http.StatusInternalServerError,"Internal Server Error")
    }
    c.String(http.StatusOK,"Successfully Posted!!")
    }
}

func getPastPosts(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var pastPosts map[string]PastPosts
		userRef := client.NewRef("server/saving-data/fireblog/pastPosts")
		if err := userRef.Get(ctx, &pastPosts); err != nil {
			log.Printf("error getting user data: %v", err)
			c.String(http.StatusInternalServerError, "Error fetching posts")
			return
		}

		// current_prices := make([]string, len(posts))
		// var wg sync.WaitGroup
		// errors := make(chan error, len(posts))

		// i := 0
		// for _, p := range posts {
		// 	wg.Add(1)
		// 	go func(i int, symbol, exchange string) {
		// 		defer wg.Done()
		// 		price, err := stockPriceHandler(symbol, exchange)
		// 		if err != nil {
		// 			errors <- err
		// 			return
		// 		}
		// 		current_prices[i] = price
		// 	}(i, p.Stock_name, p.Exchange)
		// 	i++
		// }

		// wg.Wait()
		// close(errors)

		// for err := range errors {
		// 	log.Printf("Error fetching stock price: %v", err)
		// }

		// log.Print("Current prices:", current_prices)
		r := gintemplrenderer.New(c.Request.Context(), http.StatusOK, OldPosts(pastPosts))
		c.Render(http.StatusOK, r)
	}
}

func getUsers(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var users map[string]Users
		// Hey:="RELIANCE"
		userRef := client.NewRef("server/saving-data/fireblog/users")
		if err := userRef.Get(ctx, &users); err != nil {
    		log.Fatalf("error getting user data: %v", err)
		}
		// log.Print(posts)
		r := gintemplrenderer.New(c.Request.Context(), http.StatusOK,VerifyUsers(users))
		c.Render(http.StatusOK, r)
	}
}

func verify(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		username:=c.Query("username")
		email:=c.Query("email")
		fmt.Println(email)
		userRef:=client.NewRef("server/saving-data/fireblog/users").Child(username)
		err := userRef.Update(ctx, map[string]interface{}{
        "Verified": true,
		})
		if err != nil {
        log.Fatalln("Error updating child:", err)
		c.String(http.StatusInternalServerError,"Couldn't change the user to verified")
		}
		c.String(http.StatusOK,"Verified !!")
		// sendMail(email, username)
	}
}

// func sendMail(email string, username string) {
// 	from := "info@arohanatradingacademy.org"
// 	password := "freedom@kmswealthcreations.com"

// 	to := []string{email}

// 	smtpHost := "mail.privateemail.com"
// 	smtpPort := "465"

// 	auth := smtp.PlainAuth("", from, password, smtpHost)

// 	t, err := mailTemplate(username).Parse()
// 	if err != nil {
// 		log.Fatalf("failed to parse template: %v", err)
// 	}

// 	var body bytes.Buffer

// 	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
// 	body.Write([]byte(fmt.Sprintf("Subject: Your Account has been Verified!\n%s\n\n", mimeHeaders)))

// 	err = t.Execute(&body, struct {
// 		Name    string
// 		Message string
// 	}{
// 		Name:    username,
// 		Message: "Your account has been Verified",
// 	})
// 	if err != nil {
// 		log.Fatalf("failed to execute template: %v", err)
// 	}

// 	tlsConfig := &tls.Config{
// 		ServerName: smtpHost,
// 	}

// 	conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tlsConfig)
// 	if err != nil {
// 		log.Fatalf("failed to create TLS connection: %v", err)
// 	}

// 	client, err := smtp.NewClient(conn, smtpHost)
// 	if err != nil {
// 		log.Fatalf("failed to create SMTP client: %v", err)
// 	}

// 	defer client.Quit()

// 	if err = client.Auth(auth); err != nil {
// 		log.Fatalf("failed to authenticate: %v", err)
// 	}

// 	if err = client.Mail(from); err != nil {
// 		log.Fatalf("failed to set sender: %v", err)
// 	}

// 	for _, recipient := range to {
// 		if err = client.Rcpt(recipient); err != nil {
// 			log.Fatalf("failed to set recipient: %v", err)
// 		}
// 	}

// 	writer, err := client.Data()
// 	if err != nil {
// 		log.Fatalf("failed to open data connection: %v", err)
// 	}

// 	_, err = writer.Write(body.Bytes())
// 	if err != nil {
// 		log.Fatalf("failed to write email body: %v", err)
// 	}

// 	if err = writer.Close(); err != nil {
// 		log.Fatalf("failed to close data connection: %v", err)
// 	}

// 	fmt.Println("Email Sent!")
// }

func appLogin(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var userData Users
		var username string
		var stored_password string
		username=c.PostForm("username")
		password:=c.PostForm("password")
		userRef := client.NewRef("server/saving-data/fireblog/users").Child(username)
		if err := userRef.Get(ctx, &userData); err != nil {
    		log.Fatalf("error getting user data: %v", err)
			c.String(http.StatusInternalServerError,"There was some error while fetching user data. Please try again")
			return
		}
		stored_password = userData.Password
		stored_username := userData.Username

		if username != stored_username{
			fmt.Println("The username doesn't exist! Sign-up first to get access")
			c.String(http.StatusBadRequest,"The username doesn't exist! Sign-up first to get access")
			return
		}

		err := checkPasswordHash(password,stored_password)
		if err!= nil {
			fmt.Println("Wrong password: ", err)	
			// c.String(http.StatusBadRequest, "<div id=\"notif\" class=\"notif\" hx-swap-oob=\"true\">Wrong Password!!</div>")
			c.String(http.StatusBadRequest,"Wrong Password!!")
			return
		}
		
		erro:=utils.GenerateTokensAndSetCookies(userData.Email,c)
		if erro!=nil{
			log.Println("Error generating Token: ",erro)
			c.String(http.StatusInternalServerError,"Couldn't generate token. Please try again")
			return
		}
		c.String(http.StatusOK,username)
	}
}

func postElite(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context) {
		stock_name:=c.PostForm("name")
        buying_price:=c.PostForm("buying_price")
        target_price:=c.PostForm("target_price")
        comments:=c.PostForm("comments")
        exchange:=c.PostForm("exchange")
		current_price:=c.PostForm("current_price")

        //saving the data in the firebase db
        ref := client.NewRef("server/saving-data/fireblog/elite-posts")
		newPost := Posts{
            Comments:      comments,
            Buying_price: buying_price,
            Exchange:      exchange,
            Stock_name:    stock_name,
            Target_price:  target_price,
			Current_price: current_price,
        }

        // Generate a new key
        newKey := stock_name

        // Create a map to hold the new entry
        update := map[string]interface{}{
            newKey: newPost,
        }
        err := ref.Update(ctx, update)
    if err != nil {
        log.Fatalln("Error setting value:", err)
        c.String(http.StatusInternalServerError,"Internal Server Error")
    }
	// c.Header("Hx-Refresh","true")
	c.Header("Hx-Trigger-After-Swap","reset")
    c.String(http.StatusOK,"Successfully Posted!!")
	}
}