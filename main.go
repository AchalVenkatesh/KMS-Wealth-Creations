package main

import (
	//"fmt"
	//"log"
	//"net/http"
	//"path/filepath"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

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
	auth.GET("/posts",getPosts(ctx,client))
	auth.GET("/news",getNews(ctx,client))
	auth.GET("/logout",func(c *gin.Context){
		c.Redirect(http.StatusMovedPermanently,"http://localhost:8080/login")
	})
	// auth.GET("/settings",func(c *gin.Context){
	// 	c.HTML(http.StatusOK,"settings.html","")
	// })

	admin := router.Group("/admin")
	admin.Use(utils.AuthMiddleWare())
	admin.GET("/post",func(c *gin.Context){
		c.HTML(http.StatusOK,"admin.html","sent posts")
	})
	admin.GET("/settings",func(c *gin.Context){
		c.HTML(http.StatusOK,"post-settings.html","")
	})
	admin.POST("/post",postPosts(ctx,client))
	admin.POST("/news",postNews(ctx,client))
	admin.GET("/posts",getPostsAdmin(ctx,client))
	admin.GET("/news",getNewsAdmin(ctx,client))
	admin.DELETE("/deletePosts",deletePosts(ctx,client))
	admin.DELETE("/deleteNews",deleteNews(ctx,client))
	


	router.GET("/",func(c *gin.Context){
		c.HTML(http.StatusOK,"index.html",gin.H{})
	})
	router.Static("/images","./images")
	
	router.GET("/home",func(c *gin.Context){
		c.HTML(http.StatusOK,"Home.html","hello")
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

	
	router.GET("/stocks",stockPriceHandler())

	router.POST("/admin",adminLogin(ctx,client))
	router.POST("/signup",registerUser(ctx,client))

	router.POST("/login",login(ctx, client))
	// Run the server on port 8080
	getPosts(ctx,client)
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
		//getting data from post request form
		username:=c.PostForm("username")
		fmt.Println(username)
		Email:=c.PostForm("Email")
		fmt.Println(Email)
		password:=c.PostForm("password")
		phone_number:=c.PostForm("Phone Number")

		//hashing the password
		password, err := hashPassword(password)
		if err!=nil{
			log.Println("Error hashing the password: ",err)
			c.String(http.StatusInternalServerError, "Error hashing the password")
		}
		//saving the data in the firebase db
		ref := client.NewRef("server/saving-data/fireblog")
		usersRef := ref.Child("users")
		err = usersRef.Set(ctx, map[string]*Users{
        username: {
                Username: username,
				Email: Email,
				Password: password,
				PhoneNumber: phone_number,
        },
		})
	if err != nil {
        log.Fatalln("Error setting value:", err)
		c.String(http.StatusInternalServerError,"Internal Server Error")
	}
	c.String(http.StatusOK,"Successfully registered!")
}
}

func login(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var userData Users
		var username string
		var stored_password string
		username=c.PostForm("Email")
		fmt.Println(username)
		password:=c.PostForm("password")
		fmt.Println(password)
		userRef := client.NewRef("server/saving-data/fireblog/users").Child(username)
		if err := userRef.Get(ctx, &userData); err != nil {
    		log.Fatalf("error getting user data: %v", err)
		}
		stored_password = userData.Password
		fmt.Println(stored_password)

		err := checkPasswordHash(password,stored_password)
		if err!= nil {
			fmt.Println("Wrong password: ", err)
			c.String(http.StatusBadRequest, "Wrong Password!!")
		}
		
		erro:=utils.GenerateTokensAndSetCookies(userData.Email,c)
		if erro!=nil{
			log.Println("Error generating Token: ",erro)
		}
		
		c.Redirect(http.StatusMovedPermanently,"/auth/dashboard")
		 
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
		username=c.PostForm("Email")
		fmt.Println(username)
		password:=c.PostForm("password")
		fmt.Println(password)
		userRef := client.NewRef("server/saving-data/fireblog/admins").Child(username)
		if err := userRef.Get(ctx, &adminData); err != nil {
    		log.Fatalf("error getting user data: %v", err)
		}
		stored_password = adminData.Password
		fmt.Println(stored_password)

		err := checkPasswordHash(password,stored_password)
		if err!= nil {
			fmt.Println("Wrong password: ", err)
			c.String(http.StatusBadRequest, "Wrong Password!!")
		}
		
		erro:=utils.GenerateTokensAndSetCookies(adminData.Username,c)
		if erro!=nil{
			log.Println("Error generating Token: ",erro)
		}
		c.Redirect(http.StatusMovedPermanently,"/admin/post")
		 
	}
}

func postPosts(ctx context.Context, client *db.Client) gin.HandlerFunc{
    return func(c *gin.Context){
        //getting data from post request form
        stock_name:=c.PostForm("name")

        current_price:=c.PostForm("buying_price")

        target_price:=c.PostForm("target_price")
        comments:=c.PostForm("comments")
        exchange:=c.PostForm("exchange")

        //saving the data in the firebase db
        ref := client.NewRef("server/saving-data/fireblog/posts")
		        newPost := Posts{
            Comments:      comments,
            Current_price: current_price,
            Exchange:      exchange,
            Stock_name:    stock_name,
            Target_price:  target_price,
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

func postNews(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context)  {
		news:=c.PostForm("news")

		links:=c.PostForm("links")
		//saving the data in the firebase db
		
		ref := client.NewRef("server/saving-data/fireblog")
		usersRef := ref.Child("news")
		err := usersRef.Set(ctx, map[string]*News{
        links: {
                New: news,
				Link: links,
        },
		})
	if err != nil {
        log.Fatalln("Error setting value:", err)
		c.String(http.StatusInternalServerError,"Internal Server Error")
	}
	c.String(http.StatusOK,"Successfully Posted!!")
	}
}

func getPosts(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		var posts map[string]Posts
		// Hey:="RELIANCE"
		userRef := client.NewRef("server/saving-data/fireblog/posts")
		if err := userRef.Get(ctx, &posts); err != nil {
    		log.Fatalf("error getting user data: %v", err)
		}
		log.Print(posts)
		r := gintemplrenderer.New(c.Request.Context(), http.StatusOK,PostsTemplate(posts))
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
		log.Print(news)
		r := gintemplrenderer.New(c.Request.Context(), http.StatusOK,AdminNews(news))
		c.Render(http.StatusOK, r)
	}
}

func deletePosts(ctx context.Context, client *db.Client)gin.HandlerFunc{
	return func(c *gin.Context){
		id := c.Query("stock-name")
		userRef := client.NewRef("server/saving-data/fireblog/posts").Child(id)
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

func stockPriceHandler()gin.HandlerFunc{
	return func(c *gin.Context){
				// Replace with your Alpha Vantage API key
		// apiKey := os.Getenv("ALPHA_VANTAGE_API_KEY")
		// if apiKey == "" {
		// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "API key is missing"})
		// 	return
		// }
    symbol := c.Query("symbol")
	exchange := strings.ToUpper(c.Query("exchange"))

	if symbol == "" || exchange == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Both symbol and exchange are required"})
		return
	}

	if exchange != "BSE" && exchange != "NSE" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Exchange should be either BSE or NSE"})
		return
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error fetching stock price: %v", err)})
		return
	}
	log.Println(price)
	c.String(http.StatusOK, price)
}
}
