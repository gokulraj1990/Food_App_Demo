from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from .models import Order

@receiver(post_save, sender=Order)
def send_order_update_email(sender, instance, created, **kwargs):
    if not created:  # Only send email on update
        customer_email = instance.customer.email
        send_mail(
            'Your Order Status Has Been Updated',
            f'Hello {instance.customer.username},\n\nYour order status has been updated to: {instance.status}.',
            settings.DEFAULT_FROM_EMAIL,
            [customer_email],
            fail_silently=False,
        )
