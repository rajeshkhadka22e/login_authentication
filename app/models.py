from django.db import models

# Create your models here.
class Product(models.Model):
    product_id = models.AutoField
    Product_name = models.CharField(max_length=50,default=None)
    category = models.CharField(max_length=20,default='')
    subcategory =models.CharField(max_length=50,default='')
    price = models.IntegerField(default=0)
    desc = models.CharField(max_length=300)
    pub_date = models.DateField(auto_now_add=True)

    image = models.ImageField(upload_to='media/shop/images',default="")

    def __str__(self):
        return self.Product_name
    


class Contact(models.Model):
    msg_id = models.AutoField(primary_key=True)
    Name = models.CharField(max_length=50)
    email = models.EmailField(max_length=254, default="")
    phone = models.CharField(max_length=50)
    desc = models.CharField(max_length=500)

    def __str__(self):
        return self.Name
    