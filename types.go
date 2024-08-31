package main

const (
	alphaVantageURL    = "https://www.alphavantage.co/query"
	nseURL             = "https://www.nseindia.com/api/quote-equity?symbol="
)

type Users struct{
	Name string `form:"name"`
	Email string `form:"email"`
	Username string `form: "username"`
	Password string `form: "password"`
	PhoneNumber string `form: "phoneNumber"`
	TransactionID string `form: "transactionID"`
	Verified bool
	ReferralID string
	Elite bool
	Referrals int
}

type Admin struct{
	Username string `form:"email"`
	Password string `form:"password"`
}

type Posts struct{
	Stock_name string `form:"stock_name"`
	Buying_price string `form:"buying_price"`
	Target_price string `form:"target_price"`
	Comments string `form:"comments"`
	Exchange string `form:"exchange"`
	Current_price string `form:"current_price"`
}

type PastPosts struct{
	Stock_name string `form:"stock_name"`
	Buying_price string `form:"buying_price"`
	Target_price string `form:"target_price"`
	Target string `form:"target"`
}

type News struct{
	New string `form:"news"`
}

type BSEStockResponse struct {
	GlobalQuote struct {
		Price string `json:"05. price"`
	} `json:"Global Quote"`
}

type NSEStockResponse struct {
	PriceInfo struct {
		LastPrice float64 `json:"lastPrice"`
	} `json:"priceInfo"`
}