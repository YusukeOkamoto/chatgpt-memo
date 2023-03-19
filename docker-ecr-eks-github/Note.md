next.jsで作ったサンプルアプリをeksを使ってデプロイする方法を教えてください。また、それをgithub actionsで自動化する方法も教えてください。回答はマークダウン記法で記述してください。

Next.jsアプリケーションをAmazon EKS (Elastic Kubernetes Service) にデプロイし、GitHub Actionsを使って自動化する方法について説明します。

EKSにデプロイする手順
1. Dockerイメージの作成
まず、Next.jsアプリケーションをDockerイメージにします。

プロジェクトのルートディレクトリにDockerfileを作成してください。

```Dockerfile
FROM node:14-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci --only=production

COPY . .

RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]
```
2. Dockerイメージをコンテナレジストリにプッシュ
Dockerイメージをビルドし、Amazon ECR (Elastic Container Registry) にプッシュします。以下のコマンドを実行してください。
```bash
# ECRリポジトリを作成
aws ecr create-repository --repository-name your-repo-name

# ログインコマンドを取得
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin your-aws-account-id.dkr.ecr.us-west-2.amazonaws.com

# Dockerイメージをビルド
docker build -t your-repo-name .

# ECRにタグ付け
docker tag your-repo-name:latest your-aws-account-id.dkr.ecr.us-west-2.amazonaws.com/your-repo-name:latest

# ECRにプッシュ
docker push your-aws-account-id.dkr.ecr.us-west-2.amazonaws.com/your-repo-name:latest
```

3. Kubernetesマニフェストの作成
k8sディレクトリを作成し、以下のマニフェストファイルを作成してください。
- `deployment.yaml`
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nextjs-sample
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nextjs-sample
  template:
    metadata:
      labels:
        app: nextjs-sample
    spec:
      containers:
        - name: nextjs-sample
          image: your-aws-account-id.dkr.ecr.us-west-2.amazonaws.com/your-repo-name:latest
          ports:
            - containerPort: 3000
```
- `service.yaml`
```yaml
apiVersion: v1
kind: Service
metadata:
  name: nextjs-sample
spec:
  selector:
    app: nextjs-sample
  ports:
    - protocol: TCP
      port: 80
      targetPort: 3000
  type: LoadBalancer
```
4. EKSへのデプロイ
kubectlを使ってマニフェストを適用し、アプリケーションをデプロイします。
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```
デプロイが完了したら、LoadBalancerのIPアドレスを確認してください。
```bash
kubectl get svc nextjs-sample
```
Pアドレスが表示されたら、ブラウザでそのアドレスにアクセスしてください。Next.jsアプリケーションが表示されるはずです。

GitHub Actionsを使って自動化する方法
1. GitHub Actionsの設定
プロジェクトのルートディレクトリに.github/workflowsディレクトリを作成し、deploy.ymlファイルを作成してください。
```yaml
name: Deploy to Amazon EKS

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v2

    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: 14

    - name: Install dependencies
      run: npm ci

    - name: Build Docker image
      run: docker build -t your-repo-name .

    - name: Login to Amazon ECR
      id: login-ecr
      uses: aws-actions/amazon-ecr-login@v1

    - name: Tag and push Docker image
      run: |
        docker tag your-repo-name:latest ${{ steps.login-ecr.outputs.registry }}/your-repo-name:latest
        docker push ${{ steps.login-ecr.outputs.registry }}/your-repo-name:latest

    - name: Install and configure AWS CLI
      run: |
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
        unzip awscliv2.zip
        sudo ./aws/install
        aws eks update-kubeconfig --region us-west-2 --name your-eks-cluster-name

    - name: Deploy to Amazon EKS
      run: |
        kubectl apply -f k8s/deployment.yaml
        kubectl rollout restart deployment/nextjs-sample
        kubectl apply -f k8s/service.yaml
```
作成したdeploy.ymlファイル内のyour-repo-name、your-aws-account-id、your-eks-cluster-nameを適切な値に置き換えてください。
2. GitHub Secretsの設定
GitHub ActionsでAWSリソースにアクセスするために、AWSアクセスキーとシークレットキーをGitHub Secretsに追加します。

GitHubリポジトリのSettingsタブを開きます。
左側のメニューでSecretsを選択します。
New repository secretをクリックして、以下のシークレットを追加してください。
AWS_ACCESS_KEY_ID: AWSアクセスキー
AWS_SECRET_ACCESS_KEY: AWSシークレットキー
これで、mainブランチにプッシュすると、GitHub Actionsが実行され、自動的にEKSにデプロイされるようになります。
