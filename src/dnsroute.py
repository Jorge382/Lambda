import os
import logging
import boto3
from botocore.exceptions import ClientError

# Configuración del logger para mostrar mensajes en CloudWatch Logs
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Variables de entorno configuradas en la Lambda:
# HOSTED_ZONE_ID: ID de la zona hospedada en Route 53 donde se crearán los registros.
# DOMAIN_SUFFIX: Sufijo del dominio base, por ejemplo "campusdual.mkcampus.com"
HOSTED_ZONE_ID = os.environ.get("HOSTED_ZONE_ID")
DOMAIN_SUFFIX = os.environ.get("DOMAIN_SUFFIX", "campusdual.mkcampus.com")

def get_instance_details(instance_id, region):
    """
    Obtiene detalles de la instancia EC2, como su IP pública y tags.
    
    Si surge la pregunta “¿Cómo se obtiene la IP de la instancia?”,
    se puede hacer una llamada adicional a ec2.describe_instances para obtenerla.
    En este caso usamos boto3.resource("ec2") para obtener la información de la instancia.
    """
    try:
        ec2 = boto3.resource("ec2", region_name=region)
        instance = ec2.Instance(instance_id)
        instance.load()  # Se actualizan los atributos de la instancia
        # Se convierten los tags a un diccionario: { 'NombreTag': 'Valor' }
        tags = {tag['Key']: tag['Value'] for tag in instance.tags} if instance.tags else {}
        public_ip = instance.public_ip_address  # La IP pública de la instancia
        return public_ip, tags
    except ClientError as e:
        logger.error(f"Error al obtener detalles de la instancia {instance_id} en {region}: {e}")
        return None, {}

def create_dns_records(dns_names, ip_address):
    """
    Crea o actualiza registros DNS tipo A en Route 53 para cada nombre en 'DNS_NAMES'.
    
    Explicación de algunos conceptos:
      - boto3.client('route53'): Crea un cliente para interactuar con el servicio Route 53 de AWS.
      - UPSERT: Es una operación que actualiza un registro si ya existe o lo crea si no existe.
    """
    route53 = boto3.client("route53")
    changes = []
    
    # Procesa cada nombre separado por comas en el tag "DNS_NAMES"
    for name in dns_names:
        subdomain = name.strip()
        if not subdomain:
            continue
        # Se forma el nombre completo del dominio (FQDN)
        fqdn = f"{subdomain}.{DOMAIN_SUFFIX}"
        change = {
            'Action': 'UPSERT',  # UPSERT: Inserta o actualiza el registro DNS
            'ResourceRecordSet': {
                'Name': fqdn,
                'Type': 'A',
                'TTL': 300,
                'ResourceRecords': [{'Value': ip_address}]
            }
        }
        changes.append(change)
        logger.info(f"Preparado registro: {fqdn} -> {ip_address}")

    if not changes:
        logger.info("No hay registros DNS para actualizar.")
        return

    try:
        response = route53.change_resource_record_sets(
            HostedZoneId=HOSTED_ZONE_ID,
            ChangeBatch={
                'Comment': 'Actualización automatizada vía Lambda para instancia EC2',
                'Changes': changes
            }
        )
        logger.info(f"Respuesta de Route 53: {response}")
    except ClientError as e:
        logger.error(f"Error actualizando registros en Route 53: {e}")

def lambda_handler(event, context):
    """
    Función Lambda principal.
    
    Esta función realiza lo siguiente:
      1. Recibe el evento y valida que sea del tipo "EC2 Instance State-change Notification".
      2. Extrae la información de la instancia (ID, región, estado).
      3. Llama a get_instance_details para obtener la IP pública y los tags.
      4. Extrae el tag "DNS_NAMES" y lo separa por comas.
      5. Llama a create_dns_records para crear o actualizar registros DNS en Route 53.
    
    Ejemplo de evento típico de CloudWatch (EventBridge) para cambio de estado de EC2:
    {
      "version": "0",
      "id": "abcdef12-3456-7890-abcd-ef1234567890",
      "detail-type": "EC2 Instance State-change Notification",
      "source": "aws.ec2",
      "account": "123456789012",
      "time": "2025-02-21T12:34:56Z",
      "region": "us-west-2",
      "resources": ["arn:aws:ec2:us-west-2:123456789012:instance/i-0abcdef1234567890"],
      "detail": {
         "instance-id": "i-0abcdef1234567890",
         "state": "running"
      }
    }
    """
    logger.info("Evento recibido: %s", event)
    
    # Validación: Se procesa solo si el evento es de cambio de estado de instancia EC2
    if event.get("detail-type") != "EC2 Instance State-change Notification":
        logger.info("El evento no es de cambio de estado de EC2. Se omite procesamiento.")
        return

    state = event.get("detail", {}).get("state")
    if state != "running":
        logger.info(f"Estado de la instancia: {state}. Se procesa solo cuando está 'running'.")
        return

    instance_id = event.get("detail", {}).get("instance-id")
    region = event.get("region")
    if not instance_id or not region:
        logger.error("Falta 'instance-id' o 'region' en el evento.")
        return

    # Obtener la IP pública y los tags de la instancia
    public_ip, tags = get_instance_details(instance_id, region)
    if not public_ip:
        logger.error("La instancia no tiene IP pública. No se procederá con la actualización DNS.")
        return

    # Se extrae el tag "DNS_NAMES" que contiene los nombres separados por comas
    dns_tag = tags.get("DNS_NAMES")
    if not dns_tag:
        logger.info("La instancia no tiene el tag 'DNS_NAMES'.")
        return

    # Se utiliza el método split para separar los nombres por comas y limpiar espacios adicionales
    dns_names = [name.strip() for name in dns_tag.split(",") if name.strip()]
    if not dns_names:
        logger.info("El tag 'DNS_NAMES' no contiene nombres válidos.")
        return

    # Se procede a crear o actualizar los registros DNS en Route 53
    create_dns_records(dns_names, public_ip)

